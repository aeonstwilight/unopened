"""One place that deduplicates, allowlists, defangs and caps indicators, whichever
analyzer found them."""

from __future__ import annotations

from typing import Any

from .allowlist import Allowlist
from .defang import defang
from .extract import Hit, context_for, extract

TYPE_ORDER = [
    "url", "domain", "ipv4", "ipv6", "email", "hostname", "mac_address", "unc_path",
    "file_path", "registry_key",
]


class IndicatorSet:
    def __init__(self, allowlist: Allowlist, max_indicators: int):
        self.allowlist = allowlist
        self.max_indicators = max_indicators
        self.found: dict[tuple[str, str], dict[str, Any]] = {}
        self.allowlisted: set[tuple[str, str]] = set()
        self.truncated = False

    def add(self, hit: Hit, *, source: str, offset: int | None = None,
            encoding: str | None = None, context: str = "") -> None:
        key = (hit.kind, hit.value)
        entry = self.found.get(key)
        if entry is not None:
            entry["count"] += 1
            if encoding and encoding not in entry["encodings"]:
                entry["encodings"].append(encoding)
            if source not in entry["sources"]:
                entry["sources"].append(source)
            if entry["first_offset"] is None and offset is not None:
                entry["first_offset"] = offset
            return
        if key in self.allowlisted:
            return
        if self.allowlist.allows(hit.kind, hit.value):
            self.allowlisted.add(key)
            return
        if len(self.found) >= self.max_indicators:
            self.truncated = True
            return
        self.found[key] = {
            "type": hit.kind,
            "value": defang(hit.kind, hit.value),
            "raw": hit.value,
            "count": 1,
            "first_offset": offset,
            "encodings": [encoding] if encoding else [],
            "sources": [source],
            "tags": list(hit.tags),
            "context": context if context != hit.value else "",
        }

    def add_text(self, text: str, *, source: str, offset: int | None = None,
                 encoding: str | None = None) -> None:
        for hit in extract(text):
            self.add(hit, source=source, offset=offset, encoding=encoding,
                     context=context_for(text))

    def merge(self, entries: list[dict[str, Any]], allowlisted: list[list[str]]) -> None:
        """Merge the output of another IndicatorSet (e.g. from a worker process)."""
        self.allowlisted.update((k, v) for k, v in allowlisted)
        for e in entries:
            key = (e["type"], e["raw"])
            if key in self.found:
                mine = self.found[key]
                mine["count"] += e["count"]
                mine["sources"] += [s for s in e["sources"] if s not in mine["sources"]]
                mine["encodings"] += [x for x in e["encodings"] if x not in mine["encodings"]]
            elif len(self.found) < self.max_indicators:
                self.found[key] = dict(e)
            else:
                self.truncated = True

    def entries(self) -> list[dict[str, Any]]:
        def order(e: dict[str, Any]) -> tuple[int, int]:
            offset = e["first_offset"]
            return (TYPE_ORDER.index(e["type"]), -1 if offset is None else offset)

        return sorted(self.found.values(), key=order)

    def allowlisted_keys(self) -> list[list[str]]:
        return [list(k) for k in sorted(self.allowlisted)]

    def allowlisted_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for kind, _ in self.allowlisted:
            counts[kind] = counts.get(kind, 0) + 1
        return counts
