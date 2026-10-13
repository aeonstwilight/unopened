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
_NUM = r"(?:&H[0-9a-fA-F]+|0x[0-9a-fA-F]+|\d+)"
CHAR_CODE_RUNS = [  # three or more char codes in a row
    re.compile(rf"(?i)(?:\bChrW?\$?\(\s*{_NUM}\s*\)\s*[&+]\s*){{2,}}\bChrW?\$?\(\s*{_NUM}\s*\)"),
    re.compile(rf"(?i)(?:\[char\]\s*{_NUM}\s*\+\s*){{2,}}\[char\]\s*{_NUM}"),
    re.compile(rf"fromCharCode\(\s*{_NUM}(?:\s*,\s*{_NUM}){{2,}}\s*\)"),
    re.compile(rf"(?i)\[char\[\]\]\s*\(\s*{_NUM}(?:\s*,\s*{_NUM}){{2,}}"),
]
_NUM_TOKEN = re.compile(r"(?i)&H([0-9a-f]+)|0x([0-9a-f]+)|(\d+)")


def _spells_something(run: str) -> bool:
    """A char-code run hides text only if it spells visible ASCII: obfuscation hides URLs,
    commands and API names. M5 corpus 2: slmgr.vbs builds the UTF-8 byte-order mark,
    Chr(239) + Chr(187) + Chr(191), to check a file's encoding; whitespace runs such as
    Chr(13) & Chr(10) & Chr(9) are not text either."""
    visible = 0
    for h, x, d in _NUM_TOKEN.findall(run):
        code = int(h, 16) if h else int(x, 16) if x else int(d)
        if 33 <= code <= 126:
            visible += 1
    return visible >= 3


LITERAL = re.compile(r"""'[^'\r\n]*'|"[^"\r\n]*\"""")
LITERAL_CHAIN = re.compile(
    r"""(?:(?:'[^'\r\n]*'|"[^"\r\n]*")\s*[+&]\s*){2,}(?:'[^'\r\n]*'|"[^"\r\n]*")""")
CHAIN_MIN = 4   # literals joined back to back
CHAINS_MIN = 3  # this many such chains is a pattern, not one formatting line
LONG_CHAIN = 8  # or one chain this long


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

    # Shape, not count: obfuscation chains char codes and literals together (Chr(104) &
    # Chr(116) & Chr(116) & Chr(112) spells "http"); ordinary code uses them one at a time
    # (Chr(34) & name & Chr(34)). M5 corpus 2: slmgr.vbs and jQuery have hundreds of
    # isolated ones and were called obfuscated. Runs are found in the text as written.
    char_runs = sum(1 for rx in CHAR_CODE_RUNS for m in rx.finditer(text)
                    if _spells_something(m.group(0)))
    chains = [len(LITERAL.findall(m.group(0))) for m in LITERAL_CHAIN.finditer(text)]
    heavy_concat = (sum(1 for n in chains if n >= CHAIN_MIN) >= CHAINS_MIN
                    or any(n >= LONG_CHAIN for n in chains))
    encoded = (techniques & {"base64"}) | ({"char codes"} if char_runs else set())
    out.data["obfuscation_shape"] = {"char_code_runs": char_runs,
                                     "literal_chains": sum(1 for n in chains if n >= CHAIN_MIN),
                                     "longest_chain": max(chains, default=0)}
    if encoded or heavy_concat:
        what = sorted(encoded) + (["heavy string concatenation"] if heavy_concat else [])
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
