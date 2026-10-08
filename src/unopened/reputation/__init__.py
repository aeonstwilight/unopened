"""Opt-in hash reputation lookups: MalwareBazaar first, VirusTotal second.

Only SHA256 hashes are sent; file contents and names never leave the machine. API keys
come from the environment (ABUSECH_API_KEY, VT_API_KEY), never from the command line.
Every source's outcome is recorded: found, not found, skipped (no key), rate limited or
error. "Not found" means unknown, never clean.
"""

from __future__ import annotations

import json
import os
import re
import urllib.parse
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

MB_URL = "https://mb-api.abuse.ch/api/v1/"
VT_URL = "https://www.virustotal.com/api/v3/files/"
TIMEOUT = 10.0
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

Transport = Callable[[str, str, dict[str, str], bytes | None, float], tuple[int, bytes]]


class TransportError(Exception):
    """Mirror of transport.TransportError so callers need not import the network module."""

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind


def default_transport() -> Transport:
    from . import transport  # imported only when a lookup actually happens

    def send(method: str, url: str, headers: dict[str, str], body: bytes | None,
             timeout: float) -> tuple[int, bytes]:
        try:
            return transport.request(method, url, headers, body, timeout)
        except transport.TransportError as exc:
            raise TransportError(exc.kind, str(exc)) from exc

    return send


def _json(body: bytes) -> dict[str, Any]:
    try:
        doc = json.loads(body.decode("utf-8", errors="replace"))
    except ValueError:
        return {}
    return doc if isinstance(doc, dict) else {}


def outcome(source: str, status: str, detail: str = "", **data: Any) -> dict[str, Any]:
    return {"source": source, "status": status, "detail": detail, "data": data}


def malwarebazaar(sha256: str, key: str | None, send: Transport) -> dict[str, Any]:
    if not key:
        return outcome("malwarebazaar", "skipped", "ABUSECH_API_KEY is not set")
    body = urllib.parse.urlencode({"query": "get_info", "hash": sha256}).encode()
    try:
        status, raw = send("POST", MB_URL, {"Auth-Key": key,
                                            "Content-Type": "application/x-www-form-urlencoded"},
                           body, TIMEOUT)
    except TransportError as exc:
        return outcome("malwarebazaar", "error", f"{exc.kind}: {exc}")
    doc = _json(raw)
    qs = doc.get("query_status")
    if status in (401, 403) or qs in ("unknown_auth_key", "user_blacklisted"):
        return outcome("malwarebazaar", "error", f"authentication failed ({qs or status})")
    if status == 429:
        return outcome("malwarebazaar", "rate_limited", "too many requests")
    if qs in ("hash_not_found", "no_results"):
        return outcome("malwarebazaar", "not_found", "MalwareBazaar has no record of this hash")
    if status != 200 or qs != "ok" or not doc.get("data"):
        return outcome("malwarebazaar", "error", f"unexpected answer (HTTP {status}, {qs})")
    entry = doc["data"][0] if isinstance(doc["data"], list) else {}
    return outcome(
        "malwarebazaar", "found", "MalwareBazaar knows this hash",
        signature=entry.get("signature"),
        tags=entry.get("tags") or [],
        first_seen=entry.get("first_seen"),
        file_type=entry.get("file_type"),
        file_name=entry.get("file_name"),
        delivery_method=entry.get("delivery_method"),
        link=f"https://bazaar.abuse.ch/sample/{sha256}/",
    )


def virustotal(sha256: str, key: str | None, send: Transport) -> dict[str, Any]:
    if not key:
        return outcome("virustotal", "skipped", "VT_API_KEY is not set")
    try:
        status, raw = send("GET", VT_URL + sha256, {"x-apikey": key, "Accept": "application/json"},
                           None, TIMEOUT)
    except TransportError as exc:
        return outcome("virustotal", "error", f"{exc.kind}: {exc}")
    doc = _json(raw)
    if status == 404:
        return outcome("virustotal", "not_found", "VirusTotal has no record of this hash")
    if status in (401, 403):
        return outcome("virustotal", "error", "authentication failed")
    if status == 429:
        return outcome("virustotal", "rate_limited", "quota exceeded (free keys allow 4/minute)")
    attrs = (doc.get("data") or {}).get("attributes") if status == 200 else None
    if not isinstance(attrs, dict):
        return outcome("virustotal", "error", f"unexpected answer (HTTP {status})")
    stats = attrs.get("last_analysis_stats") or {}
    first = attrs.get("first_submission_date")
    label = (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")
    return outcome(
        "virustotal", "found", "VirusTotal knows this hash",
        malicious=int(stats.get("malicious", 0) or 0),
        suspicious=int(stats.get("suspicious", 0) or 0),
        undetected=int(stats.get("undetected", 0) or 0),
        harmless=int(stats.get("harmless", 0) or 0),
        threat_label=label,
        first_submission=(datetime.fromtimestamp(first, UTC).isoformat()
                          if isinstance(first, int | float) else None),
        meaningful_name=attrs.get("meaningful_name"),
        link=f"https://www.virustotal.com/gui/file/{sha256}",
    )


SOURCES = [("malwarebazaar", "ABUSECH_API_KEY", malwarebazaar),
           ("virustotal", "VT_API_KEY", virustotal)]


def lookup_all(hashes: list[str], max_lookups: int, send: Transport | None = None,
               env: dict[str, str] | None = None) -> dict[str, dict[str, Any]]:
    """Look up each SHA256 (in order, at most max_lookups). Returns {sha256: result}."""
    env = os.environ if env is None else env
    if send is None and any(env.get(var) for _, var, _ in SOURCES):
        send = default_transport()  # no key, no network module
    results: dict[str, dict[str, Any]] = {}
    stopped: dict[str, str] = {}
    for n, sha256 in enumerate(dict.fromkeys(h.lower() for h in hashes)):
        if not SHA256_RE.match(sha256):
            continue
        if n >= max_lookups:
            results[sha256] = {"enabled": True, "skipped": f"lookup limit ({max_lookups}) reached",
                               "sources": {}}
            continue
        sources: dict[str, dict[str, Any]] = {}
        for name, key_var, func in SOURCES:
            if name in stopped:
                sources[name] = outcome(name, "skipped", stopped[name])
                continue
            result = func(sha256, env.get(key_var) or None, send)
            if result["status"] == "rate_limited":
                stopped[name] = f"not queried: {name} rate-limited an earlier lookup"
            elif result["status"] == "error" and result["detail"].startswith("authentication"):
                stopped[name] = f"not queried: {name} rejected the API key"
            sources[name] = result
        results[sha256] = {"enabled": True, "sources": sources}
    return results
