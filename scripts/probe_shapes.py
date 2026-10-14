"""Count text-shape features in scripts and unrecognized files, for validation diagnostics.

Runs a normal triage of each FILE (archives are opened with the default passwords and
their members triaged as usual; capa is skipped to save time) and, for every file or
member identified as a script, plain text or unrecognized data, prints:
- byte statistics: byte-order mark, share of NUL bytes at even and odd offsets, control
  characters, bytes above 0x7F, whether the bytes are valid UTF-8
- text statistics: lines, longest line, and how often each obfuscation shape occurs
- for Office documents, the type of each external relationship (never its target)

Only numbers, hash prefixes, file kinds and relationship types are printed. No text from
the sample, no member name and no indicator is printed, so the output is safe to copy
out of the analysis VM. Nothing is executed.

    python3 scripts/probe_shapes.py FILE [FILE ...]
"""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path
from typing import Any

from unopened import pipeline
from unopened.analyzers import Options

READ = 5 * 1024 * 1024

SHAPES: dict[str, str] = {
    # PowerShell
    "ps_backtick_in_word": r"\w`\w",
    "ps_format_operator": r"""["'](?:\{\d+\}){2,}["']\s*-f\b""",
    "ps_reverse": r"(?i)\[array\]::Reverse|\[\s*-1\s*\.\.",
    "ps_replace": r"(?i)\.replace\(|-replace\b",
    "ps_bxor": r"(?i)-bxor\b",
    "ps_split_join": r"(?i)-split\b|-join\b",
    "ps_invoke": r"(?i)\biex\b|invoke-expression|\.invoke\(|&\s*\(\s*\$|\.\s*\(\s*\$",
    "ps_var_concat_run": r"(?:\$[\w{}:]+\s*\+\s*){3,}\$[\w{}:]+",
    "ps_frombase64": r"(?i)frombase64string",
    "ps_decompress": r"(?i)gzipstream|deflatestream|decompress",
    "ps_reflection_load": r"(?i)reflection\.assembly|::load\(",
    # batch
    "bat_substring_expansion": r"%\w+:~-?\d+(?:,-?\d+)?%",
    "bat_var_run": r"(?:%\w+%){4,}",
    "bat_caret_in_word": r"(?:\w\^){3,}",
    "bat_set_line": r"(?im)^\s*set\s",
    "bat_echo_redirect": r"(?im)^\s*echo\s.*>>?",
    "bat_self_reference": r"%~f0|%~dpnx0|%0\b",
    "bat_powershell": r"(?i)powershell",
    "bat_certutil": r"(?i)certutil",
    # JavaScript / VBScript
    "js_eval_or_function": r"\beval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(",
    "js_activex": r"(?i)ActiveXObject|WScript\.CreateObject|GetObject\s*\(",
    "js_split_join": r"\.split\(|\.join\(",
    "js_replace": r"\.replace\(",
    "js_hex_escape": r"\\x[0-9a-fA-F]{2}",
    "js_unicode_escape": r"\\u[0-9a-fA-F]{4}",
    "vb_execute": r"(?i)\bExecute(?:Global)?\b|\bEval\s*\(",
    "vb_replace": r"(?i)\bReplace\s*\(",
    "vb_chr": r"(?i)\bChrW?\$?\s*\(",
    "vb_strreverse": r"(?i)\bStrReverse\b",
    "vb_mid": r"(?i)\bMid\$?\s*\(",
    "vb_createobject": r"(?i)CreateObject\s*\(",
    # any language
    "base64_run_1k": r"[A-Za-z0-9+/]{1000,}={0,2}",
    "hex_run_1k": r"(?:[0-9a-fA-F]{2}){500,}",
    "long_literal_10k": r"""'[^'\n]{10000,}'|"[^"\n]{10000,}\"""",
    "comment_line": r"(?m)^\s*(?:'|rem\s|::|//|#)",
}
COMPILED = {k: re.compile(v) for k, v in SHAPES.items()}


def byte_stats(data: bytes) -> dict[str, Any]:
    bom = ("utf-8" if data.startswith(b"\xef\xbb\xbf") else
           "utf-16le" if data.startswith(b"\xff\xfe") else
           "utf-16be" if data.startswith(b"\xfe\xff") else "none")
    even, odd = data[0::2], data[1::2]
    controls = sum(1 for b in data if b < 32 and b not in (0, 9, 10, 13))
    try:
        data.decode("utf-8")
        utf8 = True
    except UnicodeDecodeError as exc:
        utf8 = f"no (first bad byte at offset {exc.start:,})"
    return {
        "bom": bom,
        "nul_even": round(even.count(0) / max(len(even), 1), 3),
        "nul_odd": round(odd.count(0) / max(len(odd), 1), 3),
        "control_chars": controls,
        "high_bytes": round(sum(1 for b in data if b >= 0x80) / max(len(data), 1), 3),
        "utf8_valid": utf8,
    }


def decode(data: bytes, stats: dict[str, Any]) -> str:
    if stats["bom"] in ("utf-16le", "utf-16be") or stats["nul_odd"] > 0.3:
        enc = "utf-16be" if stats["bom"] == "utf-16be" or stats["nul_even"] > 0.3 else "utf-16le"
        return data.decode(enc, errors="replace")
    return data.decode("utf-8", errors="replace")


def text_stats(text: str) -> dict[str, Any]:
    lines = text.splitlines() or [""]
    non_ascii = sum(1 for c in text if ord(c) > 127)
    out: dict[str, Any] = {
        "chars": len(text),
        "lines": len(lines),
        "longest_line": max(len(x) for x in lines),
        "lines_over_1k": sum(1 for x in lines if len(x) > 1000),
        "non_ascii_chars": round(non_ascii / max(len(text), 1), 3),
    }
    for key, rx in COMPILED.items():
        n = sum(1 for _ in rx.finditer(text))
        if n:
            out[key] = n
    return out


seen: list[tuple[str, dict[str, Any]]] = []
_identify = pipeline.identify


def probing_identify(path: Path, name: str | None = None):
    file_type = _identify(path, name=name)
    if file_type.kind in ("unknown", "script", "text"):
        with path.open("rb") as f:
            data = f.read(READ)
        stats = byte_stats(data)
        info = {"kind": file_type.kind, "subtype": file_type.subtype,
                "identified_by": (file_type.details or {}).get("identified_by", "content"),
                "size": path.stat().st_size, **stats, **text_stats(decode(data, stats))}
        seen.append((hashlib.sha256(path.read_bytes()).hexdigest()[:16], info))
    return file_type


def office_rel_types(report: Any, pad: str) -> None:
    for node in pipeline.walk(report):
        r = node.result("office")
        if r is None:
            continue
        for rel in (r.data or {}).get("external_relationships", []):
            print(f"{pad}office external relationship: type={rel['type']!r} in part "
                  f"{rel['part']!r}")


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    pipeline.identify = probing_identify
    options = Options(hunt=False, timeouts={"capa": 0.01})
    for arg in argv:
        seen.clear()
        path = Path(arg)
        report = pipeline.triage(path, options)
        print("=" * 70)
        print(report.hashes.get("sha256", "")[:16], report.file_size,
              report.file_type.kind if report.file_type else "?")
        for digest, info in seen:
            print(f"  {digest}:")
            for k, v in info.items():
                print(f"    {k}: {v}")
        office_rel_types(report, "  ")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
