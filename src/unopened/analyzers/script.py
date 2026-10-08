"""PowerShell, JavaScript/JScript, VBScript and batch scripts.

The script is read as text. Deobfuscation is limited to text transformations (see
unopened.deobfuscate); the script is never run or evaluated.
"""

from __future__ import annotations

import re
import tomllib
from functools import cache
from importlib import resources
from typing import Any

from ..deobfuscate import deobfuscate
from ..model import AnalyzerOutput, Finding, Severity
from . import Context

MAX_TEXT = 5 * 1024 * 1024
MAX_SHOWN = 4_000
LONG_LINE = 2_000
NOISY_CONCAT = 10  # this many joined fragments is obfuscation, not style


@cache
def keyword_table() -> dict[str, list[dict[str, Any]]]:
    text = resources.files("unopened").joinpath("data/script_keywords.toml").read_text("utf-8")
    table = tomllib.loads(text)
    for entries in table.values():
        for e in entries:
            e["regex"] = re.compile(e["pattern"])
    return table


def scan_keywords(language: str, texts: list[str]) -> list[dict[str, Any]]:
    hits = []
    for entry in keyword_table().get(language, []):
        for text in texts:
            m = entry["regex"].search(text)
            if m:
                hits.append({
                    "id": entry["id"], "severity": entry["severity"], "title": entry["title"],
                    "tags": entry.get("tags", []), "match": m.group(0)[:200],
                })
                break
    return hits


def keyword_findings(prefix: str, hits: list[dict[str, Any]], where: str) -> list[Finding]:
    findings = [
        Finding(f"{prefix}.{h['id']}", Severity(h["severity"]), h["title"],
                f"Matched {h['match']!r} in {where}.")
        for h in hits
    ]
    tags = {t for h in hits for t in h["tags"]}
    if {"download", "execute"} <= tags:
        findings.append(Finding(
            f"{prefix}.download_execute", Severity.HIGH, "Downloads something and runs code",
            "The script both fetches content from the internet and runs programs or code: the "
            "typical shape of a downloader.",
        ))
    return findings


def read_text(data: bytes) -> str:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    return data.decode("utf-8", errors="replace").lstrip("﻿")


def analyze_script(ctx: Context) -> AnalyzerOutput:
    language = ctx.file_type.subtype or "unknown"
    with ctx.path.open("rb") as f:
        raw = f.read(MAX_TEXT + 1)
    out = AnalyzerOutput()
    if len(raw) > MAX_TEXT:
        out.not_checked.append(f"Script text beyond the first {MAX_TEXT:,} bytes")
        raw = raw[:MAX_TEXT]
    text = read_text(raw)
    result = deobfuscate(text)
    if result.truncated:
        out.not_checked.append("Deobfuscated output beyond the size cap")

    techniques = result.techniques()
    concat_steps = sum(layer.count for layer in result.layers
                       if layer.technique == "string concatenation")
    longest = max((len(line) for line in text.splitlines()), default=0)
    out.data = {
        "language": language,
        "characters": len(text),
        "lines": text.count("\n") + 1,
        "longest_line": longest,
        "layers": [{"technique": layer.technique, "count": layer.count}
                   for layer in result.layers],
        "deobfuscated": result.text[:MAX_SHOWN] if result.changed else None,
        "deobfuscated_truncated": result.changed and len(result.text) > MAX_SHOWN,
    }

    hits = scan_keywords(language, [text, result.text] if result.changed else [text])
    out.data["keywords"] = hits
    out.findings += keyword_findings("script", hits, "the script")

    encoded = techniques & {"base64", "char codes"}
    if encoded or concat_steps >= NOISY_CONCAT:
        what = sorted(encoded) + (["heavy string concatenation"]
                                  if concat_steps >= NOISY_CONCAT else [])
        out.findings.append(Finding(
            "script.obfuscated", Severity.MEDIUM, "Script is obfuscated",
            f"Uses {', '.join(what)} to hide its text. The decoded form is shown in the "
            "Script section and was searched for keywords and indicators.",
        ))
    if longest > LONG_LINE:
        out.findings.append(Finding(
            "script.long_line", Severity.LOW, f"Very long line ({longest:,} characters)",
            "Long single lines usually hold encoded data or packed code.",
        ))
    if result.changed:
        out.data["indicator_texts"] = [["script", line] for line in result.text.splitlines()
                                       if line.strip()]
    return out
