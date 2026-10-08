"""YARA scan with a user-supplied rules directory (or single rules file).

Each rule file is compiled on its own first, so one broken file is reported and the
rest still run. The namespace of a rule is its file's path relative to the rules
directory. Matched data is shown as text when printable, hex otherwise, and capped.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..model import AnalyzerOutput, Finding, Severity
from . import AnalyzerUnavailable, Context

RULE_SUFFIXES = {".yar", ".yara"}
MAX_INSTANCES = 5
MAX_MATCH_BYTES = 64
MAX_MATCHES = 200

SEVERITY_WORDS = {
    "critical": Severity.HIGH, "high": Severity.HIGH, "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO,
    "informational": Severity.INFO,
}


def rule_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    return sorted(p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in RULE_SUFFIXES)


def _namespace(root: Path, path: Path) -> str:
    if root.is_file():
        return path.stem
    return path.relative_to(root).with_suffix("").as_posix()


def _externals(ctx: Context) -> dict[str, str]:
    # Common external variables used by public rule sets (e.g. signature-base).
    return {
        "filename": ctx.path.name,
        "filepath": ctx.path.name,
        "extension": ctx.path.suffix.lower(),
        "filetype": ctx.file_type.kind.upper(),
        "owner": "",
    }


def analyze_yara(ctx: Context) -> AnalyzerOutput:
    import yara

    root = ctx.options.yara_rules
    if root is None:
        raise AnalyzerUnavailable(
            "no YARA rules configured; pass --yara-rules DIR or set UNOPENED_YARA_RULES"
        )
    if not root.exists():
        raise AnalyzerUnavailable(f"YARA rules path {root} does not exist")
    files = rule_files(root)
    if not files:
        raise AnalyzerUnavailable(f"no .yar or .yara files under {root}")

    out = AnalyzerOutput()
    externals = _externals(ctx)
    good: dict[str, str] = {}
    for path in files:
        ns = _namespace(root, path)
        try:
            yara.compile(filepath=str(path), externals=externals)
        except yara.Error as exc:
            out.errors.append(f"rule file {ns}: {exc}")
            continue
        good[ns] = str(path)
    if not good:
        raise ValueError(f"none of the {len(files)} YARA rule file(s) compiled: {out.errors[0]}")

    rules = yara.compile(filepaths=good, externals=externals)
    timeout = max(1, int(ctx.options.timeout_for("yara")))
    matches = rules.match(data=ctx.path.read_bytes(), timeout=timeout, externals=externals)

    out.data = {
        "rules_path": str(root),
        "rule_files": len(files),
        "rule_files_compiled": len(good),
        "rule_count": sum(1 for _ in rules),
        "matches": [_describe(m) for m in matches[:MAX_MATCHES]],
    }
    if len(matches) > MAX_MATCHES:
        out.not_checked.append(f"YARA matches beyond the first {MAX_MATCHES} are not listed")
    if out.errors:
        out.not_checked.append(
            f"{len(out.errors)} YARA rule file(s) failed to compile, so their rules did not run"
        )
    for m in out.data["matches"]:
        out.findings.append(_finding(m))
    return out


def _render(data: bytes) -> str:
    clipped = data[:MAX_MATCH_BYTES]
    suffix = "..." if len(data) > MAX_MATCH_BYTES else ""
    if all(32 <= b < 127 for b in clipped):
        return clipped.decode("ascii") + suffix
    even = clipped[: len(clipped) // 2 * 2]
    if even and all(b == 0 for b in even[1::2]) and all(32 <= b < 127 for b in even[0::2]):
        return "utf-16: " + even.decode("utf-16-le") + suffix
    return "hex:" + clipped.hex() + suffix


def _describe(match: Any) -> dict[str, Any]:
    strings = []
    for s in match.strings:
        instances = list(s.instances)
        strings.append({
            "identifier": s.identifier,
            "count": len(instances),
            "instances": [
                {"offset": i.offset, "length": i.matched_length, "data": _render(i.matched_data)}
                for i in instances[:MAX_INSTANCES]
            ],
        })
    meta = {k: v for k, v in match.meta.items() if isinstance(v, str | int | float | bool)}
    return {
        "rule": match.rule,
        "namespace": match.namespace,
        "tags": list(match.tags),
        "meta": meta,
        "strings": strings,
    }


def _severity(meta: dict[str, Any]) -> Severity:
    word = str(meta.get("severity", "")).strip().lower()
    if word in SEVERITY_WORDS:
        return SEVERITY_WORDS[word]
    score = meta.get("score")
    if isinstance(score, int | float) and not isinstance(score, bool):
        if score >= 75:
            return Severity.HIGH
        if score < 40:
            return Severity.LOW
    return Severity.MEDIUM


def _finding(m: dict[str, Any]) -> Finding:
    meta = m["meta"]
    about = meta.get("description") or meta.get("desc") or ""
    author = f" Rule author: {meta['author']}." if meta.get("author") else ""
    hits = ", ".join(f"{s['identifier']} x{s['count']}" for s in m["strings"]) or "condition only"
    return Finding(
        "yara.match",
        _severity(meta),
        f"YARA rule matched: {m['rule']}",
        (f"{about}. " if about else "")
        + f"Namespace {m['namespace']}; matched strings: {hits}.{author} "
        "A match means the file contains what the rule looks for; check what the rule "
        "is meant to detect before drawing conclusions.",
    )
