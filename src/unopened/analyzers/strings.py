"""Plain string extraction (ASCII and UTF-16LE) and indicator extraction over them.

Decoded and stack strings come from the separate floss analyzer (PE files only).
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

from ..indicators.collect import IndicatorSet
from ..indicators.extract import context_for, extract
from ..model import AnalyzerOutput, Finding, Severity
from . import Context


def iter_strings(data: bytes, min_length: int):
    """Yield (offset, encoding, text) for printable runs of at least min_length chars."""
    ascii_re = re.compile(rb"[\x20-\x7e\t]{%d,}" % min_length)
    utf16_re = re.compile(rb"(?:[\x20-\x7e\t]\x00){%d,}" % min_length)
    for m in ascii_re.finditer(data):
        yield m.start(), "ascii", m.group().decode("ascii")
    for m in utf16_re.finditer(data):
        yield m.start(), "utf-16le", m.group().decode("utf-16-le")


def analyze_strings(ctx: Context) -> AnalyzerOutput:
    opts = ctx.options
    data = ctx.path.read_bytes()
    out = AnalyzerOutput()
    counts: Counter[str] = Counter()
    found = IndicatorSet(opts.allowlist, opts.max_indicators)
    truncated_strings = False

    for offset, encoding, text in iter_strings(data, opts.min_string_length):
        if sum(counts.values()) >= opts.max_strings:
            truncated_strings = True
            break
        counts[encoding] += 1
        for hit in extract(text):
            found.add(hit, source="strings", offset=offset, encoding=encoding,
                      context=context_for(text))

    indicators = found.entries()
    out.data = {
        "min_length": opts.min_string_length,
        "ascii_strings": counts["ascii"],
        "utf16_strings": counts["utf-16le"],
        "truncated": truncated_strings,
        "indicators": indicators,
        "allowlisted": found.allowlisted_keys(),
        "allowlist_source": opts.allowlist.source,
    }
    if truncated_strings:
        out.not_checked.append(
            f"Strings after the first {opts.max_strings:,} were not examined for indicators"
        )
    if found.truncated:
        out.not_checked.append(
            f"Indicators beyond the first {opts.max_indicators:,} unique values were dropped"
        )
    return out


def summarize_indicators(indicators: list[dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []
    by_type = Counter(i["type"] for i in indicators)
    network = {k: by_type[k] for k in ("url", "domain", "ipv4", "ipv6", "email") if by_type[k]}
    if network:
        parts = ", ".join(f"{n} {k}" for k, n in network.items())
        public_ips = sum(1 for i in indicators if "public" in i["tags"])
        extra = f" including {public_ips} public IP address(es)" if public_ips else ""
        findings.append(Finding(
            "indicators.network",
            Severity.INFO, "Network indicators found",
            f"{parts}{extra}. See the Indicators section; these are pivots, not verdicts.",
        ))
    persistence = sorted({
        tag.split(":", 1)[1]
        for i in indicators if i["type"] == "registry_key"
        for tag in i["tags"] if tag.startswith("persistence:")
    })
    if persistence:
        findings.append(Finding(
            "indicators.persistence_registry",
            Severity.LOW, "References registry locations used for persistence",
            f"{'; '.join(persistence)}. Programs that start themselves automatically write "
            "here; so do some legitimate installers.",
        ))
    return findings
