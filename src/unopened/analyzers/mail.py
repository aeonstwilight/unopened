"""Email analyzer: the reported message itself, not only its attachments.

Reads an .eml (RFC 5322) message, or an Outlook .msg through its MAPI properties and
saved transport headers, and reports:
- who it claims to be from, where replies go, and the receiving server's SPF, DKIM and
  DMARC results;
- look-alike and impersonated domains in the sender, reply-to and links;
- links whose visible text names a different site than they go to, and forms in the body;
- attachments, written with the bounded member writer and triaged recursively, like
  archive members.

Static only (rule 1): the message is parsed as text with the standard library. HTML is
read by a tokenizer for tags and attributes; nothing is rendered, no link is followed and
no remote image is fetched.
"""

from __future__ import annotations

import email
import email.policy
import re
import tomllib
from dataclasses import dataclass, field
from email.message import EmailMessage, Message
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from importlib import resources
from typing import Any
from urllib.parse import urlsplit

from ..extraction import CHUNK, MemberWriter, basename
from ..model import AnalyzerOutput, Finding, Severity
from . import AnalyzerUnavailable, Context
from .office import EXECUTABLE_EXTENSIONS

MAX_PARTS = 1_000  # MIME parts walked per message
MAX_MIME_DEPTH = 30
MAX_LINKS = 500
MAX_BODY_CHARS = 2_000_000  # decoded body text kept for links and indicators
MAX_RECEIVED = 20
MAX_LISTED = 10  # examples named in a finding
HTML_ATTACHMENT_EXTENSIONS = {"htm", "html", "shtml", "xhtml", "svg", "mht", "mhtml"}
URL_IN_TEXT = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'()\[\]{}]+", re.IGNORECASE)
DOMAIN_LIKE = re.compile(
    r"^(?:https?://)?(?:www\.)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:?#].*)?$", re.IGNORECASE)
IP_HOST = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$|^\[?[0-9a-f:]+\]?$", re.IGNORECASE)
AUTH_RESULT = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)
FAILING = {"fail", "softfail", "permerror"}
# Second-level labels under country codes that act like a TLD (example.co.uk).
SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu", "ne", "or", "go", "gob", "nic"}
LOOKALIKE_SWAPS = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"),
                   ("5", "s"), ("@", "a"), ("$", "s")]


# Small helpers -----------------------------------------------------------------------

def org_domain(host: str) -> str:
    """The registrable part of a host name, approximately: the last two labels, or three
    when the second-level label is a country-code pseudo-TLD (example.co.uk). Without a
    public-suffix list this is a heuristic; it only decides whether two names belong to
    the same organization."""
    host = host.strip().strip(".").lower().rstrip(">").lstrip("<[").rstrip("]")
    labels = [x for x in host.split(".") if x]
    if len(labels) <= 2:
        return ".".join(labels)
    if len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def address_domain(address: str) -> str:
    _, addr = parseaddr(address or "")
    addr = addr or address or ""
    return addr.rsplit("@", 1)[-1].strip().strip("<>").lower() if "@" in addr else ""


def url_host(url: str) -> str:
    try:
        host = urlsplit(url.strip()).hostname or ""
    except ValueError:
        return ""
    return host.lower()


def _extension(name: str) -> str:
    base = basename(name or "").strip().rstrip(".").lower()
    return base.rsplit(".", 1)[-1] if "." in base else ""


def load_brands() -> dict[str, list[str]]:
    text = resources.files("unopened").joinpath("data/brands.toml").read_text("utf-8")
    return {name: [d.lower() for d in entry.get("domains", [])]
            for name, entry in tomllib.loads(text).items()}


def _normalize(label: str) -> str:
    for a, b in LOOKALIKE_SWAPS:
        label = label.replace(a, b)
    return label


def impersonated_brand(host: str, brands: dict[str, list[str]]) -> str | None:
    """The brand a host name imitates, or None. A host belongs to a brand when it is one
    of the brand's domains or a subdomain of one."""
    host = host.lower().strip(".")
    if not host:
        return None
    normalized = _normalize(host)
    for brand, domains in brands.items():
        if any(host == d or host.endswith("." + d) for d in domains):
            continue
        if re.search(rf"(?:^|[.\-_0-9]){re.escape(brand)}", normalized):
            return brand
    return None


# HTML links and forms ----------------------------------------------------------------

class _HtmlScan(HTMLParser):
    """Collects links (href plus visible text), forms, meta refreshes and frames."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[dict[str, str]] = []
        self.forms: list[dict[str, Any]] = []
        self.refresh: list[str] = []
        self.frames: list[str] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a" and a.get("href"):
            self._close()
            self._href, self._text = a["href"].strip(), []
        elif tag == "form":
            self.forms.append({"action": a.get("action", "").strip(),
                               "method": a.get("method", "get").lower(), "password": False})
        elif tag == "input" and a.get("type", "").lower() == "password" and self.forms:
            self.forms[-1]["password"] = True
        elif tag == "input" and a.get("type", "").lower() == "password":
            self.forms.append({"action": "", "method": "", "password": True})
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            m = re.search(r"url\s*=\s*['\"]?([^'\"]+)", a.get("content", ""), re.IGNORECASE)
            if m:
                self.refresh.append(m.group(1).strip())
        elif tag in ("iframe", "frame") and a.get("src"):
            self.frames.append(a["src"].strip())

    def handle_endtag(self, tag: str) -> None:
        if tag == "a":
            self._close()

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)

    def _close(self) -> None:
        if self._href is not None and len(self.links) < MAX_LINKS:
            text = " ".join("".join(self._text).split())
            self.links.append({"href": self._href, "text": text[:300], "where": "html"})
        self._href = None

    def close(self) -> None:
        super().close()
        self._close()


# Message parsing ---------------------------------------------------------------------

@dataclass
class Parsed:
    """What both formats produce for the shared checks."""

    headers: Message | None
    plain: list[str] = field(default_factory=list)
    html: list[str] = field(default_factory=list)
    # (name, content type, payload bytes or None, skipped reason or None)
    attachments: list[tuple[str, str, bytes | None, str | None]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)  # things not checked


def parse_eml(data: bytes) -> Parsed:
    msg = email.message_from_bytes(data, policy=email.policy.default)
    parsed = Parsed(headers=msg)
    counter = [0]
    _walk(msg, parsed, counter, depth=0, top=True)
    if counter[0] >= MAX_PARTS:
        parsed.notes.append(f"MIME parts after the first {MAX_PARTS}")
    return parsed


def _walk(part: Message, parsed: Parsed, counter: list[int], depth: int, top: bool) -> None:
    if counter[0] >= MAX_PARTS:
        return
    counter[0] += 1
    ctype = (part.get_content_type() or "").lower()
    if ctype == "message/rfc822" and not top:
        inner = part.get_payload()
        inner = inner[0] if isinstance(inner, list) and inner else inner
        raw = inner.as_bytes() if isinstance(inner, Message) else None
        subject = str(inner.get("subject", "")) if isinstance(inner, Message) else ""
        name = part.get_filename() or f"{(subject or 'attached message')[:60]}.eml"
        parsed.attachments.append((name, ctype, raw, None if raw else "could not be read"))
        return
    if part.is_multipart():
        if depth >= MAX_MIME_DEPTH:
            parsed.notes.append(f"MIME parts nested deeper than {MAX_MIME_DEPTH} levels")
            return
        payload = part.get_payload()
        for sub in payload if isinstance(payload, list) else []:
            _walk(sub, parsed, counter, depth + 1, top=False)
        return
    disposition = (part.get_content_disposition() or "").lower()
    name = part.get_filename()
    if ctype in ("text/plain", "text/html") and disposition != "attachment" and not name:
        text = _text_of(part)
        (parsed.html if ctype == "text/html" else parsed.plain).append(text)
        return
    if ctype in ("application/pkcs7-mime", "application/x-pkcs7-mime"):
        parsed.notes.append("S/MIME-encrypted content (cannot be read without the key)")
    if ctype == "application/ms-tnef" or (name or "").lower() == "winmail.dat":
        parsed.notes.append("Outlook TNEF (winmail.dat) contents")
    try:
        payload = part.get_payload(decode=True)
    except Exception:
        payload = None
    parsed.attachments.append((
        name or f"unnamed part ({ctype or 'no type'})", ctype, payload,
        None if payload is not None else "payload could not be decoded",
    ))


def _text_of(part: Message) -> str:
    try:
        if isinstance(part, EmailMessage):
            return str(part.get_content())
    except Exception:
        pass
    raw = part.get_payload(decode=True) or b""
    charset = part.get_content_charset() or "utf-8"
    try:
        return raw.decode(charset, errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


# Outlook .msg ------------------------------------------------------------------------

MSG_ATTACH = "__attach_version1.0_#"


def parse_msg(ctx: Context) -> Parsed:
    try:
        import olefile
    except ImportError as exc:
        raise AnalyzerUnavailable("olefile is needed for Outlook .msg files: "
                                  "pip install 'unopened[office]'") from exc
    ole = olefile.OleFileIO(str(ctx.path))
    try:
        return _read_msg(ole, ctx.options.limits.max_member_size)
    finally:
        ole.close()


def _msg_prop(ole: Any, prefix: list[str], tag: str, limit: int) -> str | bytes | None:
    for suffix, kind in (("001F", "utf16"), ("001E", "ansi"), ("0102", "binary")):
        path = prefix + [f"__substg1.0_{tag}{suffix}"]
        if not ole.exists("/".join(path)):
            continue
        if ole.get_size("/".join(path)) > limit:
            return None
        raw = ole.openstream(path).read()
        if kind == "utf16":
            return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
        if kind == "ansi":
            return raw.decode("cp1252", errors="replace").rstrip("\x00")
        return raw
    return None


def _as_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _read_msg(ole: Any, limit: int) -> Parsed:
    transport = _as_text(_msg_prop(ole, [], "007D", limit))
    if transport.strip():
        headers = email.message_from_string(transport.strip() + "\n\n",
                                            policy=email.policy.default)
    else:
        # No saved transport headers (a draft, or a message saved before sending): build the
        # basic ones from MAPI properties so the address checks still run.
        headers = EmailMessage()
        name = _as_text(_msg_prop(ole, [], "0C1A", limit))
        addr = (_as_text(_msg_prop(ole, [], "5D01", limit))
                or _as_text(_msg_prop(ole, [], "0C1F", limit)))
        for key, value in (("From", f"{name} <{addr}>" if addr else name),
                           ("Subject", _as_text(_msg_prop(ole, [], "0037", limit))),
                           ("To", _as_text(_msg_prop(ole, [], "0E04", limit)))):
            if value.strip():
                try:
                    headers[key] = value
                except Exception:
                    pass
    parsed = Parsed(headers=headers)
    if not transport.strip():
        parsed.notes.append("Sender authentication results (the .msg has no saved "
                            "transport headers)")
    if body := _as_text(_msg_prop(ole, [], "1000", limit)):
        parsed.plain.append(body)
    html = _msg_prop(ole, [], "1013", limit)
    if html:
        parsed.html.append(_as_text(html))
    storages = sorted({entry[0] for entry in ole.listdir(streams=True, storages=True)
                       if entry and entry[0].startswith(MSG_ATTACH)})
    for storage in storages[:MAX_PARTS]:
        prefix = [storage]
        name = (_as_text(_msg_prop(ole, prefix, "3707", limit))
                or _as_text(_msg_prop(ole, prefix, "3704", limit))
                or _as_text(_msg_prop(ole, prefix, "3001", limit))
                or f"attachment {storage[-8:]}")
        ctype = _as_text(_msg_prop(ole, prefix, "370E", limit)) or ""
        if ole.exists(f"{storage}/__substg1.0_3701000D"):
            parsed.attachments.append((name, "message/rfc822", None,
                                       "embedded Outlook message: listed, not extracted"))
            parsed.notes.append(f"Embedded Outlook message {name!r} (listed, not extracted)")
            continue
        data_path = f"{storage}/__substg1.0_37010102"
        if not ole.exists(data_path):
            parsed.attachments.append((name, ctype, None, "no attachment data (linked or OLE "
                                                          "object attachment)"))
            continue
        if ole.get_size(data_path) > limit:
            parsed.attachments.append((name, ctype, None,
                                       f"over the per-member limit ({limit:,} bytes)"))
            continue
        parsed.attachments.append((name, ctype, ole.openstream(data_path).read(), None))
    return parsed


# The analyzer ------------------------------------------------------------------------

def analyze_email(ctx: Context) -> AnalyzerOutput:
    out = AnalyzerOutput()
    fmt = "msg" if ctx.file_type.kind == "ole" else "eml"
    if fmt == "msg":
        parsed = parse_msg(ctx)
    else:
        parsed = parse_eml(ctx.path.read_bytes())
    brands = load_brands()
    headers = _headers(parsed.headers)
    received = _received(parsed.headers)
    auth = _auth(parsed.headers)
    links, forms, extras = _links(parsed)
    writer = MemberWriter(ctx.extract_dir, ctx.options.limits, ctx.files_left, ctx.bytes_left)
    attachments = _extract(parsed, writer, out)
    out.data = {
        "format": fmt, "headers": headers, "received": received, "auth": auth,
        "links": links, "forms": forms, "refresh": extras["refresh"],
        "frames": extras["frames"], "attachments": attachments,
        "members": writer.members, "extracted_files": writer.used_files,
        "extracted_bytes": writer.used_bytes,
        "body_chars": sum(len(t) for t in parsed.plain + parsed.html),
    }
    _sender_findings(out, headers, auth, brands)
    _link_findings(out, links, forms, extras, brands)
    _attachment_findings(out, attachments)
    out.not_checked += parsed.notes
    if writer.stopped:
        out.not_checked.append(f"Attachments after the extraction limit ({writer.stopped})")
    for m in writer.members:
        if m.get("skipped"):
            out.not_checked.append(f"Attachment {m['name']} ({m['skipped']})")
    _indicators(out, parsed, headers, links)
    return out


def _header(msg: Message | None, name: str) -> str:
    if msg is None:
        return ""
    try:
        value = msg.get(name)
    except Exception:
        return ""
    return " ".join(str(value).split()) if value is not None else ""


def _headers(msg: Message | None) -> dict[str, str]:
    names = {"from": "From", "sender": "Sender", "reply_to": "Reply-To",
             "return_path": "Return-Path", "to": "To", "cc": "Cc", "subject": "Subject",
             "date": "Date", "message_id": "Message-ID", "x_mailer": "X-Mailer",
             "x_originating_ip": "X-Originating-IP"}
    out = {key: _header(msg, name) for key, name in names.items()}
    return {k: v for k, v in out.items() if v}


def _all(msg: Message | None, name: str) -> list[str]:
    if msg is None:
        return []
    try:
        return [" ".join(str(v).split()) for v in (msg.get_all(name) or [])]
    except Exception:
        return []


def _received(msg: Message | None) -> list[str]:
    return [line[:400] for line in _all(msg, "Received")[:MAX_RECEIVED]]


def _auth(msg: Message | None) -> dict[str, Any]:
    """SPF, DKIM and DMARC as the receiving server recorded them. Only the topmost
    Authentication-Results header is used: it is added by the last server, the one the
    recipient's organization runs. Lower ones can be forged by the sender."""
    results = _all(msg, "Authentication-Results") or _all(msg, "ARC-Authentication-Results")
    auth: dict[str, Any] = {"source": None}
    if results:
        top = results[0]
        auth["source"] = "Authentication-Results"
        auth["raw"] = top[:600]
        for mech, result in AUTH_RESULT.findall(top):
            auth.setdefault(mech.lower(), result.lower())
    spf = _all(msg, "Received-SPF")
    if spf and "spf" not in auth:
        auth["spf"] = spf[0].split()[0].lower() if spf[0].split() else ""
        auth["source"] = auth["source"] or "Received-SPF"
    return auth


def _addresses(value: str) -> list[tuple[str, str]]:
    try:
        return [(n, a) for n, a in getaddresses([value]) if a or n]
    except Exception:
        return []


def _sender_findings(out: AnalyzerOutput, h: dict[str, str], auth: dict[str, Any],
                     brands: dict[str, list[str]]) -> None:
    f = out.findings
    from_pairs = _addresses(h.get("from", ""))
    display, from_addr = from_pairs[0] if from_pairs else ("", "")
    from_domain = address_domain(from_addr)
    from_org = org_domain(from_domain) if from_domain else ""

    if auth.get("source") is None:
        out.not_checked.append(
            "Sender authentication (SPF, DKIM, DMARC): the message carries no results from "
            "a receiving server, e.g. it was saved before delivery or exported by a client "
            "that drops them")
    else:
        failed = {m: auth[m] for m in ("spf", "dkim", "dmarc") if auth.get(m) in FAILING}
        if auth.get("dmarc") in FAILING:
            f.append(Finding(
                "email.dmarc_fail", Severity.HIGH, "DMARC failed for the sender's domain",
                f"The receiving server recorded dmarc={auth['dmarc']}: the message is not "
                f"authenticated as coming from {from_domain or 'the From domain'}. The From "
                "address is likely spoofed.",
            ))
        other = {m: r for m, r in failed.items() if m != "dmarc"}
        if other:
            f.append(Finding(
                "email.auth_fail", Severity.MEDIUM,
                "Sender authentication failed: " + ", ".join(f"{m}={r}" for m, r in other.items()),
                "Recorded by the receiving server. Forwarding and mailing lists can break SPF "
                "and DKIM, so read this with the other findings.",
            ))
        if not failed and all(auth.get(m) in (None, "none", "neutral") for m in
                              ("spf", "dkim", "dmarc")):
            f.append(Finding(
                "email.auth_none", Severity.LOW, "No passing sender authentication",
                "SPF, DKIM and DMARC are absent or 'none', so nothing vouches for the sender.",
            ))

    if "@" in display:
        shown = address_domain(display)
        if shown and org_domain(shown) != from_org:
            f.append(Finding(
                "email.display_name_address", Severity.HIGH,
                "Display name shows a different email address",
                f"The name reads {display!r}, but the message is from {from_addr!r}. Mail "
                "clients often show only the name.",
            ))
    if display and from_domain:
        named = impersonated_brand(re.sub(r"[^a-z0-9.\-]", "-", display.lower()), brands)
        if named and not any(from_domain == d or from_domain.endswith("." + d)
                             for d in brands[named]):
            f.append(Finding(
                "email.display_name_brand", Severity.MEDIUM,
                f"Display name uses the {named} brand, but the address is not theirs",
                f"{display!r} sent from {from_domain!r}.",
            ))

    for key, label in (("from", "sender"), ("reply_to", "reply-to address"),
                       ("return_path", "return path")):
        for _, addr in _addresses(h.get(key, "")):
            dom = address_domain(addr)
            if dom.startswith("xn--") or ".xn--" in dom:
                f.append(Finding(
                    "email.punycode_domain", Severity.MEDIUM,
                    f"The {label} uses an internationalized (punycode) domain",
                    f"{dom!r} can display as letters that look like a familiar name.",
                ))
            brand = impersonated_brand(dom, brands)
            if brand:
                f.append(Finding(
                    "email.lookalike_sender", Severity.HIGH if key != "return_path"
                    else Severity.MEDIUM,
                    f"The {label} domain imitates {brand}",
                    f"{dom!r} contains the {brand} name but is not one of its domains.",
                ))

    reply = [address_domain(a) for _, a in _addresses(h.get("reply_to", ""))]
    reply = [d for d in reply if d]
    if from_org and reply and any(org_domain(d) != from_org for d in reply):
        f.append(Finding(
            "email.reply_to_mismatch", Severity.MEDIUM,
            "Replies go to a different organization than the sender",
            f"From {from_domain!r}, Reply-To {', '.join(sorted(set(reply)))!r}. A common setup "
            "for invoice and payroll fraud: the reply reaches the attacker.",
        ))
    rp = [address_domain(a) for _, a in _addresses(h.get("return_path", ""))]
    rp = [d for d in rp if d]
    if from_org and rp and org_domain(rp[0]) != from_org:
        f.append(Finding(
            "email.return_path_mismatch", Severity.LOW,
            "Bounce address is at a different domain than the From address",
            f"Return-Path {rp[0]!r}. Normal for mailing services and newsletters; notable "
            "together with other findings.",
        ))


def _links(parsed: Parsed) -> tuple[list[dict[str, str]], list[dict[str, Any]], dict]:
    links: list[dict[str, str]] = []
    forms: list[dict[str, Any]] = []
    extras: dict[str, list[str]] = {"refresh": [], "frames": []}
    for html in parsed.html:
        scan = _HtmlScan()
        try:
            scan.feed(html[:MAX_BODY_CHARS])
            scan.close()
        except Exception:
            pass
        links += scan.links
        forms += scan.forms
        extras["refresh"] += scan.refresh
        extras["frames"] += scan.frames
    seen = {link["href"] for link in links}
    for text in parsed.plain:
        for m in URL_IN_TEXT.finditer(text[:MAX_BODY_CHARS]):
            url = m.group().rstrip(".,;:!?")
            if url not in seen and len(links) < MAX_LINKS:
                seen.add(url)
                links.append({"href": url, "text": "", "where": "text"})
    for link in links:
        link["domain"] = url_host(link["href"])
    return links[:MAX_LINKS], forms, extras


def _shown_domain(text: str) -> str:
    m = DOMAIN_LIKE.match(text.strip())
    return m.group(1).lower() if m else ""


def _link_findings(out: AnalyzerOutput, links: list[dict[str, str]],
                   forms: list[dict[str, Any]], extras: dict, brands: dict) -> None:
    f = out.findings
    mismatched = []
    for link in links:
        shown = _shown_domain(link.get("text", ""))
        target = link.get("domain", "")
        if shown and target and org_domain(shown) != org_domain(target):
            link["note"] = f"text shows {shown}"
            mismatched.append(f"{shown} -> {target}")
    if mismatched:
        f.append(Finding(
            "email.link_text_mismatch", Severity.MEDIUM,
            f"Link text names a different site than the link opens ({len(mismatched)})",
            "; ".join(mismatched[:MAX_LISTED]) + ". Mailing services also do this for click "
            "tracking, so check the destinations.",
        ))
    for form in forms:
        target = form.get("action") or "(no action: submits to the page itself)"
        f.append(Finding(
            "email.html_form", Severity.HIGH,
            "The email body contains a form" + (" with a password field"
                                                if form.get("password") else ""),
            f"Submits to {target!r}. Legitimate mail almost never asks for input in the "
            "message itself; this is a credential-harvesting pattern.",
        ))
    scheme_links = [lk["href"][:80] for lk in links
                    if lk["href"].lower().startswith(("javascript:", "data:", "vbscript:"))]
    if scheme_links:
        f.append(Finding(
            "email.script_link", Severity.HIGH, "Links that run script or embed data",
            ", ".join(scheme_links[:MAX_LISTED]),
        ))
    ip_links = sorted({lk["domain"] for lk in links if IP_HOST.match(lk.get("domain", ""))
                       and lk["domain"]})
    if ip_links:
        f.append(Finding(
            "email.ip_link", Severity.MEDIUM, "Links point to raw IP addresses",
            ", ".join(ip_links[:MAX_LISTED]),
        ))
    imitating = sorted({f"{lk['domain']} ({b})" for lk in links
                        if (b := impersonated_brand(lk.get("domain", ""), brands))})
    if imitating:
        f.append(Finding(
            "email.lookalike_link", Severity.HIGH,
            "Links go to domains imitating a known brand",
            ", ".join(imitating[:MAX_LISTED]),
        ))
    puny = sorted({lk["domain"] for lk in links if "xn--" in lk.get("domain", "")})
    if puny:
        f.append(Finding(
            "email.punycode_link", Severity.MEDIUM,
            "Links use internationalized (punycode) domains", ", ".join(puny[:MAX_LISTED]),
        ))
    if extras["refresh"]:
        f.append(Finding(
            "email.meta_refresh", Severity.MEDIUM, "HTML body redirects automatically",
            ", ".join(extras["refresh"][:MAX_LISTED]),
        ))
    if extras["frames"]:
        f.append(Finding(
            "email.html_frame", Severity.MEDIUM, "HTML body loads a frame from elsewhere",
            ", ".join(extras["frames"][:MAX_LISTED]),
        ))
    if links:
        f.append(Finding(
            "email.links", Severity.INFO, f"Links ({len(links)})",
            "Listed below and as indicators (defanged). None were followed.",
        ))


def _extract(parsed: Parsed, writer: MemberWriter, out: AnalyzerOutput) -> list[dict]:
    listed = []
    for name, ctype, payload, skipped in parsed.attachments:
        entry = {"name": name, "content_type": ctype,
                 "size": len(payload) if payload is not None else None}
        listed.append(entry)
        if payload is None:
            writer.record(name, None, skipped=f"not extracted: {skipped}", attached_to="email")
            continue
        sink = writer.open(name, len(payload), None, attached_to="email")
        if sink is None:
            continue
        try:
            with sink:
                for i in range(0, len(payload), CHUNK):
                    sink.write(payload[i:i + CHUNK])
        except Exception as exc:
            out.errors.append(f"attachment {name}: {type(exc).__name__}: {exc}")
    return listed


def _attachment_findings(out: AnalyzerOutput, attachments: list[dict]) -> None:
    for a in attachments:
        ext = _extension(a["name"])
        if ext in EXECUTABLE_EXTENSIONS:
            out.findings.append(Finding(
                "email.attachment_executable", Severity.HIGH,
                f"Attachment with a runnable extension: {a['name']}",
                f"Windows runs .{ext} files on double-click. Analyzed below.",
            ))
        elif ext in HTML_ATTACHMENT_EXTENSIONS:
            out.findings.append(Finding(
                "email.attachment_html", Severity.MEDIUM,
                f"HTML attachment: {a['name']}",
                "Opens in a browser from the local disk, out of reach of URL filtering: used "
                "for fake sign-in pages and HTML smuggling.",
            ))
    if attachments:
        out.findings.append(Finding(
            "email.attachments", Severity.INFO, f"Attachments ({len(attachments)})",
            "Each one is extracted and analyzed below.",
        ))


def _indicators(out: AnalyzerOutput, parsed: Parsed, h: dict[str, str],
                links: list[dict[str, str]]) -> None:
    texts = [["email", link["href"]] for link in links]
    for key in ("from", "sender", "reply_to", "return_path", "x_originating_ip"):
        if h.get(key):
            texts.append(["email", h[key]])
    if out.data["received"]:
        # The oldest hop names the sending side; newer ones are usually the recipient's own
        # mail servers, which are noise as hunting pivots.
        texts.append(["email", out.data["received"][-1]])
    for html in parsed.html:
        texts.append(["email", re.sub(r"<[^>]+>", " ", html)[:MAX_BODY_CHARS]])
    budget = MAX_BODY_CHARS
    for body in parsed.plain:
        texts.append(["email", body[:budget]])
        budget -= min(len(body), budget)
        if budget <= 0:
            break
    out.data["indicator_texts"] = texts
