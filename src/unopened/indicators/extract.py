"""Find indicators in strings: URLs, domains, IP addresses, email addresses, Windows file
paths and registry keys.

Matches are validated, not just pattern-matched: IPs must parse, domains must end in a
real top-level domain (data/tlds.txt), and a few common sources of noise (file names
with TLD-like extensions, .NET namespaces, member access in scripts) are dropped.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from functools import cache
from importlib import resources
from urllib.parse import urlsplit

URL_RE = re.compile(r"(?i)(?:https?|ftps?)://[^\s\"'<>`{}|\\^\x00-\x1f\x7f]+")
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_TLD = r"(?:[A-Za-z]{2,63}|xn--[A-Za-z0-9-]{1,59})"
DOMAIN_RE = re.compile(rf"(?<![\w.@-])(?:{_LABEL}\.)+{_TLD}(?![\w-])")
EMAIL_RE = re.compile(rf"(?<![\w.%+-])[A-Za-z0-9._%+-]{{1,64}}@(?:{_LABEL}\.)+{_TLD}(?![\w-])")
IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)")
IPV6_RE = re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")

_PATH_CHARS = r"[^\\/:*?\"<>|\r\n\t\x00]"
_PATH_TAIL = rf"{_PATH_CHARS}+(?:\\{_PATH_CHARS}+)*\\?"
WINPATH_RE = re.compile(rf"(?<![\w])[A-Za-z]:\\(?:{_PATH_TAIL})")
ENVPATH_RE = re.compile(rf"%[A-Za-z_][A-Za-z0-9_()]*%\\(?:{_PATH_TAIL})")
UNC_RE = re.compile(rf"(?<![\w\\])\\\\[A-Za-z0-9._$-]+(?:@SSL)?(?:@\d+)?\\(?:{_PATH_TAIL})")
_HIVES = (
    r"HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG"
    r"|HKLM|HKCU|HKCR|HKU|HKCC"
)
_REG_TAIL = r"[^\r\n\t\"\x00<>|]{2,512}"
REGISTRY_RE = re.compile(rf"(?i)\b(?:{_HIVES}):?\\{_REG_TAIL}")
REGISTRY_NOHIVE_RE = re.compile(
    r"(?i)(?<![\\\w])(?:SOFTWARE|SYSTEM)\\(?:Microsoft|CurrentControlSet|ControlSet\d{3}|Classes"
    rf"|Policies|WOW6432Node)\\{_REG_TAIL}"
)

# TLDs that collide with common file extensions. A bare "name.zip" is far more likely
# a file name than a domain, unless it appears inside a URL or email address. Keep this
# list short: every entry hides real two-label domains on that TLD when they appear bare.
FILE_EXTENSION_TLDS = {
    "zip", "mov", "py", "sh", "pl", "rs", "md", "ps", "so", "cat", "pub", "one", "run", "cab",
    "ts",
}

PERSISTENCE_KEYS = {
    "\\currentversion\\run": "Run/RunOnce autostart key",
    "\\currentversion\\winlogon": "Winlogon (Shell/Userinit) key",
    "\\image file execution options": "Image File Execution Options (debugger hijack)",
    "appinit_dlls": "AppInit_DLLs",
    "\\currentcontrolset\\services": "service configuration",
    "\\active setup\\installed components": "Active Setup",
    "\\explorer\\shell folders\\startup": "Startup folder location",
}

TRAILING_PUNCT = ".,;:!?'\""
CLOSERS = {")": "(", "]": "[", "}": "{"}
MAX_CONTEXT = 200


@cache
def known_tlds() -> frozenset[str]:
    text = resources.files("unopened").joinpath("data/tlds.txt").read_text(encoding="utf-8")
    return frozenset(
        line.strip().lower() for line in text.splitlines()
        if line.strip() and not line.startswith("#")
    )


def is_known_tld(domain: str) -> bool:
    return domain.rsplit(".", 1)[-1].lower() in known_tlds()


def _trim(value: str) -> str:
    """Strip trailing punctuation and unbalanced closing brackets from a match."""
    while value:
        last = value[-1]
        if last in TRAILING_PUNCT or last.isspace():
            value = value[:-1]
        elif last in CLOSERS and value.count(last) > value.count(CLOSERS[last]):
            value = value[:-1]
        else:
            break
    return value


def _valid_ip(value: str, version: int) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    return ip if ip.version == version else None


def _looks_like_identifier(domain: str, text: str, end: int) -> bool:
    """Noise heuristics for bare domains (not inside a URL or email)."""
    labels = domain.split(".")
    if len(labels) == 2 and labels[-1].lower() in FILE_EXTENSION_TLDS:
        return True
    # .NET namespaces and class names: System.Security, Microsoft.Win32.Registry
    if all(lab[:1].isupper() and any(c.islower() for c in lab) for lab in labels):
        return True
    # Member access or a call in script/source code: obj.click(), x.style =
    following = text[end : end + 2].lstrip()
    return following[:1] in ("(", "=") and not following.startswith("==")


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    kind: str  # url, email, ipv4, ipv6, domain
    noise: bool = False

    def value(self, text: str) -> str:
        return text[self.start : self.end]


def _network_candidates(text: str) -> list[Span]:
    spans: list[Span] = []
    for m in URL_RE.finditer(text):
        value = _trim(m.group())
        try:
            host = urlsplit(value).hostname
        except ValueError:
            continue
        if host:
            spans.append(Span(m.start(), m.start() + len(value), "url"))
    for m in EMAIL_RE.finditer(text):
        if is_known_tld(m.group()):
            spans.append(Span(m.start(), m.end(), "email"))
    for m in IPV4_RE.finditer(text):
        if _valid_ip(m.group(), 4):
            spans.append(Span(m.start(), m.end(), "ipv4"))
    for m in IPV6_RE.finditer(text):
        value = m.group()
        if len([g for g in value.split(":") if g]) >= 3 and _valid_ip(value, 6):
            spans.append(Span(m.start(), m.end(), "ipv6"))
    for m in DOMAIN_RE.finditer(text):
        value = m.group()
        if is_known_tld(value):
            noise = _looks_like_identifier(value, text, m.end())
            spans.append(Span(m.start(), m.end(), "domain", noise))
            continue
        # "drop.example.com.exe": not a domain as a whole, but a chat client may still
        # linkify the domain inside it. Keep the longest valid prefix, for defanging only.
        labels = value.split(".")
        for n in range(len(labels) - 1, 1, -1):
            prefix = ".".join(labels[:n])
            if is_known_tld(prefix):
                spans.append(Span(m.start(), m.start() + len(prefix), "domain", noise=True))
                break
    return spans


def _non_overlapping(spans: list[Span]) -> list[Span]:
    chosen: list[Span] = []
    last_end = -1
    for span in sorted(spans, key=lambda s: (s.start, -(s.end - s.start))):
        if span.start >= last_end:
            chosen.append(span)
            last_end = span.end
    return chosen


def find_network_spans(text: str) -> list[tuple[int, int, str]]:
    """Every network indicator in text, noise included. Used for defanging, where a
    false positive costs nothing and a miss leaves a live link."""
    if not any(c in text for c in ".:@"):
        return []
    return [(s.start, s.end, s.kind) for s in _non_overlapping(_network_candidates(text))]


@dataclass(frozen=True)
class Hit:
    kind: str  # url, domain, ipv4, ipv6, email, file_path, unc_path, registry_key
    value: str
    tags: tuple[str, ...] = ()


def _ip_tags(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, text: str) -> tuple[str, ...]:
    if ip.is_unspecified:
        tags = ["unspecified"]
    elif ip.is_loopback:
        tags = ["loopback"]
    elif ip.is_multicast:
        tags = ["multicast"]
    elif ip.is_link_local:
        tags = ["link_local"]
    elif ip.is_private:
        tags = ["private_or_reserved"]
    elif ip.is_reserved:
        tags = ["reserved"]
    else:
        tags = ["public"]
    if ip.version == 4 and text.strip() == str(ip):
        octets = str(ip).split(".")
        if octets[-1] == "0" or all(len(o) == 1 for o in octets):
            tags.append("possible_version_number")
    return tuple(tags)


def _host_hit(host: str, text: str) -> Hit | None:
    host = host.strip("[]").lower()
    for version in (4, 6):
        ip = _valid_ip(host, version)
        if ip:
            return Hit(f"ipv{version}", str(ip), _ip_tags(ip, text))
    if "." in host and is_known_tld(host) and DOMAIN_RE.fullmatch(host):
        return Hit("domain", host)
    return None


def extract(text: str) -> list[Hit]:
    """All indicators in one string, noise removed. URL and email hosts are also
    reported as domains/IPs so analysts can pivot on them."""
    hits: list[Hit] = []
    if any(c in text for c in ".:@"):
        for span in _non_overlapping(_network_candidates(text)):
            value = span.value(text)
            if span.kind == "url":
                hits.append(Hit("url", value))
                host = urlsplit(value).hostname
                if host and (h := _host_hit(host, text)):
                    hits.append(h)
            elif span.kind == "email":
                hits.append(Hit("email", value.lower()))
                if h := _host_hit(value.rpartition("@")[2], text):
                    hits.append(h)
            elif span.kind in ("ipv4", "ipv6"):
                ip = ipaddress.ip_address(value)
                hits.append(Hit(span.kind, str(ip), _ip_tags(ip, text)))
            elif not span.noise:
                hits.append(Hit("domain", value.lower()))
    if "\\" in text:
        hits.extend(_local_hits(text))
    return hits


def _local_hits(text: str) -> list[Hit]:
    hits: list[Hit] = []
    taken: list[tuple[int, int]] = []

    def add(kind: str, m: re.Match[str], tags: tuple[str, ...] = ()) -> None:
        value = _trim(m.group())
        start, end = m.start(), m.start() + len(value)
        if len(value) < 4 or any(s < end and start < e for s, e in taken):
            return
        taken.append((start, end))
        hits.append(Hit(kind, value, tags))

    for m in REGISTRY_RE.finditer(text):
        add("registry_key", m, _registry_tags(m.group()))
    for m in REGISTRY_NOHIVE_RE.finditer(text):
        add("registry_key", m, ("hive_not_specified", *_registry_tags(m.group())))
    for m in UNC_RE.finditer(text):
        host = m.group()[2:].split("\\", 1)[0]
        add("file_path" if host in (".", "?") else "unc_path", m)
    for regex in (WINPATH_RE, ENVPATH_RE):
        for m in regex.finditer(text):
            add("file_path", m)
    return hits


def _registry_tags(key: str) -> tuple[str, ...]:
    lowered = key.lower()
    return tuple(
        f"persistence:{label}" for needle, label in PERSISTENCE_KEYS.items() if needle in lowered
    )


def context_for(text: str) -> str:
    if len(text) <= MAX_CONTEXT:
        return text
    return text[: MAX_CONTEXT - 3] + "..."
