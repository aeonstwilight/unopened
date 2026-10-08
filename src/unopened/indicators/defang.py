"""Defanging: make indicators safe to paste into tickets and chat, where they would
otherwise become clickable links.

Convention: hxxp://example[.]com/path, 10.0.0[.]1, user[@]example[.]com.
Every piece of human-readable output passes through defang_text().
"""

from __future__ import annotations

import re
from typing import Any

_SCHEMES = {"http": "hxxp", "https": "hxxps", "ftp": "fxp", "ftps": "fxps"}
_SCHEME_RE = re.compile(r"(?i)^(https?|ftps?)://")


def defang_host(host: str) -> str:
    if ":" in host and host.count(":") >= 2:  # IPv6
        return host.replace(":", "[:]")
    if "." not in host:
        return host
    head, _, tail = host.rpartition(".")
    return f"{head}[.]{tail}"


def defang_url(url: str) -> str:
    m = _SCHEME_RE.match(url)
    if not m:
        return url
    scheme = m.group(1)
    rest = url[m.end():]
    host_end = len(rest)
    for sep in "/?#":
        idx = rest.find(sep)
        if idx != -1:
            host_end = min(host_end, idx)
    authority, path = rest[:host_end], rest[host_end:]
    userinfo, at, hostport = authority.rpartition("@")
    if hostport.startswith("["):  # [IPv6]:port
        close = hostport.find("]")
        host, port = hostport[1:close], hostport[close + 1:]
        new_hostport = f"[{defang_host(host)}]{port}"
    else:
        host, colon, port = hostport.partition(":")
        new_hostport = defang_host(host) + colon + port
    new_scheme = _SCHEMES[scheme.lower()]
    if scheme.isupper():
        new_scheme = new_scheme.upper()
    return f"{new_scheme}://{userinfo}{'[@]' if at else ''}{new_hostport}{path}"


def defang_email(email: str) -> str:
    local, _, domain = email.rpartition("@")
    return f"{local}[@]{defang_host(domain)}"


def defang_unc(path: str) -> str:
    host, sep, rest = path[2:].partition("\\")
    return "\\\\" + defang_host(host) + sep + rest


def defang(kind: str, value: str) -> str:
    if kind == "url":
        return defang_url(value)
    if kind in ("domain", "ipv4", "ipv6"):
        return defang_host(value)
    if kind == "email":
        return defang_email(value)
    if kind == "unc_path":
        return defang_unc(value)
    return value


def defang_text(text: str) -> str:
    """Defang every network indicator found anywhere in free text. Idempotent: defanged
    values no longer match the extraction patterns."""
    from .extract import find_network_spans  # local import: extract imports nothing from here

    spans = find_network_spans(text)
    if not spans:
        return text
    out, pos = [], 0
    for start, end, kind in spans:
        out.append(text[pos:start])
        out.append(defang(kind, text[start:end]))
        pos = end
    out.append(text[pos:])
    return "".join(out)


# Keys whose values are left alone: "raw" carries live indicators by design (rule 2);
# "id" and "rule" are the tool's own identifiers (e.g. "script.ps.download"), not
# indicators, even when they happen to look like domains.
UNTOUCHED_KEYS = {"raw", "id", "rule"}


def defang_tree(obj: Any) -> Any:
    """Defang all strings in a JSON-like structure, except under UNTOUCHED_KEYS."""
    if isinstance(obj, str):
        return defang_text(obj)
    if isinstance(obj, dict):
        return {
            defang_text(k) if isinstance(k, str) else k:
                (v if k in UNTOUCHED_KEYS and isinstance(v, str | dict) else defang_tree(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list | tuple):
        return [defang_tree(v) for v in obj]
    return obj
