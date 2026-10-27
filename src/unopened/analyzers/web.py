"""HTML, SVG, HTA and WSF files: smuggled payloads, redirects, credential forms, scripts.

The markup is tokenized with the standard library's HTMLParser. Nothing is rendered,
no script is run, no resource is fetched and no link is followed. Script blocks are
read as text, deobfuscated as text (unopened.deobfuscate) and searched for keywords.

HTML smuggling hides a file inside a page as base64, hex or a number array and has the
browser assemble and "download" it, so the file never crosses the mail gateway as an
attachment. Embedded payloads are decoded here as text transformations, kept only when
the decoded bytes are a recognizable file, written with the bounded member writer and
triaged recursively like archive members.
"""

from __future__ import annotations

import base64
import binascii
import re
from html.parser import HTMLParser
from typing import Any

from ..extraction import MemberWriter
from ..identify import LNK_MAGIC, OLE_MAGIC, SEVENZIP_MAGIC, VHDX_MAGIC
from ..model import AnalyzerOutput, Finding, Severity
from . import Context
from .mail import impersonated_brand, load_brands, url_host
from .script import MAX_TEXT, analyze_text, read_text

MAX_SCRIPT_CHARS = 2 * 1024 * 1024
MAX_SHOWN = 4_000
MAX_LISTED = 5
MAX_CANDIDATES = 25
MIN_B64 = 120        # characters of a bare base64 literal worth decoding
MIN_DATA_URI = 88    # characters of base64 in a data: URI (about 64 bytes)
MIN_HEX = 256
MIN_ARRAY = 256      # numbers in a byte array literal
LONG_ENCODED = 1000  # an encoded literal this long is payload-sized even when undecodable
THIN_PAGE = 400      # visible characters below which a page is only a wrapper

B64_RUN = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")  # MIN_B64
DATA_URI = re.compile(r"data:([\w.+-]+/[\w.+-]+)?((?:;[\w-]+=[^;,]*)*);base64,"
                      r"([A-Za-z0-9+/=\s]{88,})", re.I)  # MIN_DATA_URI
HEX_RUN = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){128,}(?![0-9A-Fa-f])")  # MIN_HEX
BYTE_ARRAY = re.compile(r"\[\s*((?:(?:0x[0-9a-fA-F]{1,2}|\d{1,3})\s*,\s*){255,}"
                        r"(?:0x[0-9a-fA-F]{1,2}|\d{1,3}))\s*\]")  # MIN_ARRAY
ENCODED_LITERAL = re.compile(r"['\"`]([A-Za-z0-9+/=]{1000,})['\"`]")  # LONG_ENCODED

# Smuggling steps. Pages assemble a file (Blob/File), hand it to the browser as a
# download (object URL, msSaveOrOpenBlob, a download attribute) and often click it.
# Web apps with a "download CSV" button use the same calls, so the rule also needs an
# embedded payload.
BLOB = re.compile(r"\bBlob\b|\bnew\s+File\s*\(")
DELIVER = re.compile(r"createObjectURL|msSaveOrOpenBlob|msSaveBlob|\.download\s*=|"
                     r"['\"]download['\"]|\bsaveAs\s*\(")
DECODE = re.compile(r"\batob\b|\bUint8Array\b|charCodeAt|fromCharCode|base64", re.I)
AUTO_CLICK = re.compile(r"\.click\s*\(\s*\)|dispatchEvent\s*\(|msSaveOrOpenBlob")
DOWNLOAD_NAME = re.compile(r"\.download\s*=\s*['\"`]([^'\"`\r\n]{1,120})['\"`]|"
                           r"setAttribute\(\s*['\"]download['\"]\s*,\s*['\"`]([^'\"`\r\n]{1,120})")

JS_NAVIGATE = re.compile(
    r"\b(?:window\.|document\.|top\.|self\.|parent\.)?location(?:\.href)?\s*=(?!=)\s*([^;\n]{1,200})|"
    r"\blocation\.(?:replace|assign)\s*\(\s*([^)\n]{1,200})|"
    r"\bwindow\.open\s*\(\s*([^,)\n]{1,200})")
URL_LITERAL = re.compile(r"""https?://[^\s'"`<>)]+""", re.I)
SUBMIT_JS = re.compile(r"\bfetch\s*\(|XMLHttpRequest|\$\.(?:ajax|post)\s*\(|sendBeacon\s*\(|"
                       r"\.submit\s*\(\s*\)|axios\.post")
EXFIL_SERVICE = re.compile(r"api\.telegram\.org/bot|discord(?:app)?\.com/api/webhooks|"
                           r"hooks\.slack\.com/services", re.I)

# Leading bytes of decoded payloads worth triaging, with a name extension and whether
# Windows runs it.
PAYLOAD_MAGIC: list[tuple[bytes, str, str, bool]] = [
    (b"MZ", "Windows program (PE)", "exe", True),
    (b"PK\x03\x04", "ZIP archive", "zip", False),
    (SEVENZIP_MAGIC, "7-Zip archive", "7z", False),
    (b"Rar!\x1a\x07", "RAR archive", "rar", False),
    (OLE_MAGIC, "OLE document (Office, MSI)", "doc", False),
    (b"%PDF-", "PDF document", "pdf", False),
    (LNK_MAGIC, "Windows shortcut (LNK)", "lnk", True),
    (b"\x1f\x8b\x08", "gzip data", "gz", False),
    (b"MSCF", "Cabinet archive", "cab", False),
    (b"{\\rt", "RTF document", "rtf", False),
    (VHDX_MAGIC, "Virtual hard disk (VHDX)", "vhdx", False),
]
MARKUP_START = re.compile(rb"^\s*<(?:!doctype|html|head|body|script|svg|\?xml)", re.I)


class _Scan(HTMLParser):
    """Collects scripts (with language), event handlers, links, forms, navigations,
    embedded objects, the HTA application tag and visible text."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.scripts: list[dict[str, str]] = []
        self.external_scripts: list[str] = []
        self.handlers: list[str] = []
        self.links: list[dict[str, str]] = []
        self.forms: list[dict[str, Any]] = []
        self.password_fields = 0
        self.refresh: list[str] = []
        self.frames: list[str] = []
        self.foreign_objects = 0
        self.hta: dict[str, str] | None = None
        self.title: list[str] = []
        self.visible: list[str] = []
        self._script: dict[str, str] | None = None
        self._skip = 0
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        for k, v in a.items():
            if k.startswith("on") and v.strip():
                self.handlers.append(v)
        for k in ("href", "src", "xlink:href", "action", "data", "formaction"):
            v = a.get(k, "").strip()
            if v.lower().startswith(("javascript:", "vbscript:")):
                self.handlers.append(v.split(":", 1)[1])
        if tag == "script":
            lang = (a.get("language") or a.get("type") or "javascript").lower()
            src = a.get("src", "").strip()
            if src and not src.lower().startswith("data:"):
                self.external_scripts.append(src)
            self._script = {"language": _language(lang), "source": "", "src": src}
        elif tag in ("style", "noscript", "template"):
            self._skip += 1
        elif tag == "title":
            self._in_title = True
        elif tag == "a" or (tag == "use" and a.get("xlink:href")):
            href = a.get("href") or a.get("xlink:href") or ""
            if href.strip():
                self.links.append({"href": href.strip(), "download": a.get("download", "")
                                   if "download" in a else None})
        elif tag == "form":
            self.forms.append({"action": a.get("action", "").strip(),
                               "method": a.get("method", "get").lower(), "password": False})
        elif tag == "input" and a.get("type", "").lower() == "password":
            self.password_fields += 1
            if self.forms:
                self.forms[-1]["password"] = True
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            m = re.search(r"url\s*=\s*['\"]?([^'\"]+)", a.get("content", ""), re.I)
            if m:
                self.refresh.append(m.group(1).strip())
        elif tag in ("iframe", "frame", "embed", "object"):
            src = (a.get("src") or a.get("data") or "").strip()
            if src:
                self.frames.append(src)
        elif tag == "foreignobject":
            self.foreign_objects += 1
        elif tag == "hta:application":
            self.hta = {k: v for k, v in a.items()
                        if k in ("id", "applicationname", "windowstate", "showintaskbar",
                                 "border", "caption", "sysmenu")}

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._script is not None:
            self.scripts.append(self._script)
            self._script = None
        elif tag in ("style", "noscript", "template"):
            self._skip = max(0, self._skip - 1)
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._script is not None:
            self._script["source"] += data
        elif self._in_title:
            self.title.append(data)
        elif not self._skip and sum(len(v) for v in self.visible) < 20_000:
            self.visible.append(data)

    def close(self) -> None:
        super().close()
        if self._script is not None:  # unterminated <script>: keep what was read
            self.scripts.append(self._script)
            self._script = None


def _language(value: str) -> str:
    v = value.lower()
    if "vbs" in v:
        return "vbscript"
    return "javascript"


def _cdata(text: str) -> str:
    return re.sub(r"<!\[CDATA\[|\]\]>", "", text)


def analyze_web(ctx: Context) -> AnalyzerOutput:
    kind = ctx.file_type.kind
    subtype = ctx.file_type.subtype or kind
    with ctx.path.open("rb") as f:
        raw = f.read(MAX_TEXT + 1)
    out = AnalyzerOutput()
    if len(raw) > MAX_TEXT:
        out.not_checked.append(f"Markup beyond the first {MAX_TEXT:,} bytes")
        raw = raw[:MAX_TEXT]
    text = read_text(raw)

    scan = _Scan()
    try:
        scan.feed(text)
        scan.close()
    except Exception as exc:  # HTMLParser is lenient; anything raised is reported
        out.errors.append(f"markup: {type(exc).__name__}: {exc}")

    # Script text by language: <script> blocks, event handlers, javascript: links, and
    # scripts embedded as data: URIs.
    by_lang: dict[str, list[str]] = {"javascript": [], "vbscript": []}
    for s in scan.scripts:
        by_lang[s["language"]].append(_cdata(s["source"]))
        if s["src"].lower().startswith("data:"):
            decoded = _decode_data_uri(s["src"])
            if decoded:
                by_lang[s["language"]].append(decoded.decode("utf-8", "replace"))
    by_lang["javascript"] += scan.handlers
    visible = " ".join(" ".join(scan.visible).split())
    title = " ".join(" ".join(scan.title).split())
    out.data = {
        "kind": subtype,
        "characters": len(text),
        "title": title[:200],
        "visible_characters": len(visible),
        "scripts": [{"language": s["language"], "characters": len(s["source"]),
                     "src": s["src"][:200]} for s in scan.scripts],
        "event_handlers": len(scan.handlers),
        "external_scripts": scan.external_scripts[:50],
        "links": len(scan.links),
        "forms": scan.forms[:20],
        "password_fields": scan.password_fields,
        "navigations": [],
        "payloads": [],
        "smuggling": None,
        "keywords": [],
        "layers": [],
        "deobfuscated": None,
        "hta": scan.hta,
    }

    # Deobfuscate and scan each language's script text as one script.
    script_texts: list[str] = []
    indicator_texts: list[list[str]] = []
    deob_shown: list[str] = []
    for lang, parts in by_lang.items():
        joined = "\n;\n".join(p for p in parts if p.strip())
        if not joined:
            continue
        if len(joined) > MAX_SCRIPT_CHARS:
            out.not_checked.append(f"{lang} beyond the first {MAX_SCRIPT_CHARS:,} characters")
            joined = joined[:MAX_SCRIPT_CHARS]
        sub, full = analyze_text(joined, lang, prefix="web", where="the page's scripts")
        out.findings += sub.findings
        out.not_checked += sub.not_checked
        out.data["keywords"] += sub.data.get("keywords", [])
        out.data["layers"] += [dict(x, language=lang) for x in sub.data.get("layers", [])]
        script_texts.append(joined)
        if sub.data.get("deobfuscated"):
            deob_shown.append(sub.data["deobfuscated"])
            script_texts.append(full)
        indicator_texts += sub.data.get("indicator_texts", [])
    if deob_shown:
        out.data["deobfuscated"] = "\n".join(deob_shown)[:MAX_SHOWN]
    scripts = "\n".join(script_texts)

    writer = MemberWriter(ctx.extract_dir, ctx.options.limits, ctx.files_left, ctx.bytes_left)
    _payloads(text, scripts, scan, writer, out)
    out.data["members"] = writer.members
    out.data["extracted_files"] = writer.used_files
    out.data["extracted_bytes"] = writer.used_bytes
    if writer.stopped:
        out.not_checked.append(f"Embedded payloads after the extraction limit ({writer.stopped})")
    for m in writer.members:
        if m.get("skipped"):
            out.not_checked.append(f"Embedded payload {m['name']} ({m['skipped']})")

    _smuggling(scripts, scan, out)
    _navigation(scripts, scan, visible, kind, out)
    _credentials(scripts, scan, title, visible, out)
    _type_findings(kind, subtype, scan, out)

    texts = [lk["href"] for lk in scan.links] + scan.refresh + scan.frames
    texts += [f["action"] for f in scan.forms if f["action"]] + scan.external_scripts
    texts += [n["target"] for n in out.data["navigations"]]
    indicator_texts += [["web", t] for t in texts if t and not t.lower().startswith("data:")]
    out.data["indicator_texts"] = indicator_texts
    return out


# Embedded payloads --------------------------------------------------------------------

def _decode_data_uri(uri: str) -> bytes | None:
    m = re.match(r"data:[^,]*;base64,(.*)", uri.strip(), re.I | re.S)
    if not m:
        return None
    return _b64(m.group(1))


def _b64(text: str) -> bytes | None:
    s = re.sub(r"\s+", "", text)
    s = s + "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None


def sniff(data: bytes) -> tuple[str, str, bool] | None:
    """(description, extension, runnable) of decoded bytes that are a file worth
    triaging, or None."""
    for magic, desc, ext, runnable in PAYLOAD_MAGIC:
        if data.startswith(magic):
            return desc, ext, runnable
    if len(data) > 0x8006 and data[0x8001:0x8006] == b"CD001":
        return "ISO 9660 disk image", "iso", False
    if MARKUP_START.match(data[:512]):
        return "HTML or SVG page (another layer)", "html", False
    return None


def _candidates(text: str, scripts: str, scan: _Scan) -> list[tuple[str, bytes]]:
    """(where found, decoded bytes) for every encoded blob, largest first."""
    found: list[tuple[str, bytes]] = []
    seen: set[bytes] = set()

    def add(where: str, data: bytes | None) -> None:
        if data and len(data) >= 32:
            key = data[:64] + len(data).to_bytes(8, "little")
            if key not in seen:
                seen.add(key)
                found.append((where, data))

    for m in DATA_URI.finditer(text):
        add(f"data: URI ({(m.group(1) or 'no type').lower()})", _b64(m.group(3)))
    for source in (text, scripts):
        for m in B64_RUN.finditer(source):
            add("base64 string", _b64(m.group()))
        for m in HEX_RUN.finditer(source):
            add("hex string", bytes.fromhex(m.group()))
        for m in BYTE_ARRAY.finditer(source):
            nums = [int(x, 0) for x in re.split(r"\s*,\s*", m.group(1).strip())]
            if all(0 <= n <= 255 for n in nums):
                add("number array", bytes(nums))
    found.sort(key=lambda c: -len(c[1]))
    return found[:MAX_CANDIDATES]


def _payloads(text: str, scripts: str, scan: _Scan, writer: MemberWriter,
              out: AnalyzerOutput) -> None:
    names = [n for m in DOWNLOAD_NAME.finditer(scripts) for n in m.groups() if n]
    names += [lk["download"] for lk in scan.links if lk.get("download")]
    for where, data in _candidates(text, scripts, scan):
        kind = sniff(data)
        if kind is None:
            continue
        desc, ext, runnable = kind
        n = len(out.data["payloads"]) + 1
        name = names.pop(0) if names else f"embedded-{n}.{ext}"
        record = {"name": name, "type": desc, "size": len(data), "found_in": where,
                  "runnable": runnable}
        out.data["payloads"].append(record)
        writer.write_all(name, [data], len(data), embedded_in="web", found_in=where)


# Findings -------------------------------------------------------------------------------

def _smuggling(scripts: str, scan: _Scan, out: AnalyzerOutput) -> None:
    payloads = out.data["payloads"]
    blob, deliver = BLOB.search(scripts), DELIVER.search(scripts)
    download_links = [lk for lk in scan.links if lk.get("download") is not None
                      and lk["href"].lower().startswith(("data:", "blob:"))]
    long_literal = ENCODED_LITERAL.search(scripts)
    steps = []
    if DECODE.search(scripts):
        steps.append("decodes embedded data")
    if blob:
        steps.append("assembles a file in the browser (Blob)")
    if deliver:
        steps.append("hands it to the browser as a download")
    if AUTO_CLICK.search(scripts):
        steps.append("starts the download itself")
    if download_links:
        steps.append("links to an embedded file with a download attribute")
    evidence = payloads or long_literal
    if (blob and deliver and evidence) or (download_links and payloads):
        out.data["smuggling"] = steps
        what = (", ".join(f"{p['name']} ({p['type']}, {p['size']:,} bytes)"
                          for p in payloads[:MAX_LISTED])
                or f"an encoded literal of {len(long_literal.group(1)):,} characters that did "
                   "not decode to a known file type (it may be encrypted or XOR-encoded)")
        out.findings.append(Finding(
            "web.smuggling", Severity.HIGH, "HTML smuggling: the page builds and drops a file",
            f"The page {'; '.join(steps)}. Payload: {what}. Opening the page in a browser "
            "would save the file without it ever passing the mail gateway as an attachment.",
        ))
    for p in payloads:
        fid = "web.embedded_executable" if p["runnable"] else "web.embedded_payload"
        out.findings.append(Finding(
            fid, Severity.HIGH if p["runnable"] else Severity.MEDIUM,
            f"Embedded {p['type']}: {p['name']}",
            f"Decoded from a {p['found_in']} ({p['size']:,} bytes, as a text transformation). "
            "It is analyzed below as a member.",
        ))


def _navigation(scripts: str, scan: _Scan, visible: str, kind: str,
                out: AnalyzerOutput) -> None:
    navs = out.data["navigations"]
    for target in scan.refresh:
        navs.append({"how": "meta refresh", "target": target})
    for m in JS_NAVIGATE.finditer(scripts):
        expr = next(g for g in m.groups() if g).strip()
        url = URL_LITERAL.search(expr)
        if url is None and re.match(r"""^(['"`])[^'"`]*\1\s*$""", expr):
            continue  # a fixed relative target ("#top", "page2.html") stays on the page
        navs.append({"how": "script", "target": url.group() if url else expr[:120]})
    for src in scan.frames:
        if src.lower().startswith(("http:", "https:", "//")):
            navs.append({"how": "frame or embedded object", "target": src})
    off_site = [n for n in navs if n["target"].lower().startswith(("http:", "https:", "//"))
                or n["how"] == "script"]
    if not off_site:
        return
    listed = "; ".join(f"{n['how']}: {n['target'][:100]}" for n in off_site[:MAX_LISTED])
    if kind == "svg":
        out.findings.append(Finding(
            "web.svg_redirect", Severity.HIGH, "SVG image sends the viewer to a web page",
            f"{listed}. A picture has no reason to navigate; SVG attachments that redirect "
            "are a common phishing lure.",
        ))
        return
    thin = len(visible) < THIN_PAGE and len(scan.links) <= 3
    if thin:
        out.findings.append(Finding(
            "web.redirect_lure", Severity.HIGH,
            "Page is only a wrapper that sends the viewer elsewhere",
            f"{listed}. It shows almost nothing itself ({len(visible)} visible characters): "
            "the shape of a phishing attachment that opens a remote sign-in page.",
        ))
    else:
        out.findings.append(Finding(
            "web.redirect", Severity.MEDIUM, f"Page navigates or loads content elsewhere "
            f"({len(off_site)})", listed + ". Nothing was followed.",
        ))


def _credentials(scripts: str, scan: _Scan, title: str, visible: str,
                 out: AnalyzerOutput) -> None:
    if not scan.password_fields:
        return
    brands = load_brands()
    words = re.sub(r"[^a-z0-9]+", "-", f"{title} {visible[:2000]}".lower())
    brand = next((b for b in brands if re.search(rf"(?:^|-){re.escape(b)}(?:-|$)", words)),
                 None)
    named = f" The page names {brand}." if brand else ""
    exfil = EXFIL_SERVICE.search(scripts) or any(
        EXFIL_SERVICE.search(f["action"]) for f in scan.forms)
    if exfil:
        out.findings.append(Finding(
            "web.credential_exfil", Severity.HIGH,
            "Password form sends what is typed to a messaging service",
            f"The page has a password field and posts to {exfil.group()!r}: phishing kits "
            f"deliver stolen credentials to Telegram bots and Discord webhooks.{named}",
        ))
        return
    remote = [f["action"] for f in scan.forms if f["password"]
              and f["action"].lower().startswith(("http:", "https:", "//"))]
    lookalike = [a for a in remote if impersonated_brand(url_host(a), brands)]
    if remote or SUBMIT_JS.search(scripts):
        target = (f"submits to {remote[0]!r}" if remote
                  else "sends the form with script")
        out.findings.append(Finding(
            "web.credential_form", Severity.HIGH, "Password form that submits to a web server",
            f"A local page with a password field {target}"
            + (f", a domain imitating {impersonated_brand(url_host(lookalike[0]), brands)}"
               if lookalike else "")
            + f". Saved or attached pages have no reason to collect passwords.{named}",
        ))
    else:
        out.findings.append(Finding(
            "web.password_field", Severity.MEDIUM, "Page asks for a password",
            f"It has {scan.password_fields} password field(s) but no submission was found.{named}",
        ))


def _type_findings(kind: str, subtype: str, scan: _Scan, out: AnalyzerOutput) -> None:
    has_script = bool(scan.scripts or scan.handlers)
    if kind == "svg":
        if has_script:
            out.findings.append(Finding(
                "web.svg_script", Severity.HIGH, "SVG image contains script",
                f"{len(scan.scripts)} script block(s) and {len(scan.handlers)} event "
                "handler(s). Images do not need scripts; a browser runs them when the file "
                "is opened.",
            ))
        if scan.foreign_objects:
            out.findings.append(Finding(
                "web.svg_foreign_object", Severity.MEDIUM, "SVG embeds HTML (foreignObject)",
                "Used to draw forms or frames inside an image.",
            ))
    elif subtype == "hta":
        out.findings.append(Finding(
            "web.hta", Severity.MEDIUM, "HTML Application (HTA)",
            "mshta.exe runs it with the user's full rights, outside the browser sandbox: its "
            "scripts can start programs and write files. HTA files are a common first stage.",
        ))
    elif kind == "wsf":
        out.findings.append(Finding(
            "web.wsf", Severity.INFO, "Windows Script File",
            "Windows Script Host runs its script blocks directly on double-click.",
        ))
