"""Behavior patterns: named combinations of signals (see data/behaviors.toml).

Runs after every analyzer has finished, over their findings and capa's capabilities, and
returns one finding per pattern that matched. Never looks at the sample itself.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from functools import cache
from importlib import resources
from typing import Any

from .model import AnalyzerResult, Finding, Severity, Status

SOURCE = "behavior"


class PatternError(ValueError):
    pass


@dataclass(frozen=True)
class Pattern:
    id: str
    title: str
    severity: Severity
    description: str
    groups: tuple[tuple[str, ...], ...]
    unsigned: bool = False


def _check_signal(pid: str, signal: str) -> None:
    kind, sep, value = signal.partition(":")
    if not sep:
        kind, sep, value = signal.partition("~")
        kind += "~"
    if kind not in ("capa", "capa~", "finding") or not value:
        raise PatternError(f"behavior {pid}: bad signal {signal!r}")


def parse(data: dict[str, Any]) -> list[Pattern]:
    patterns = []
    for pid, spec in data.items():
        try:
            severity = Severity(spec["severity"])
            groups = tuple(tuple(g) for g in spec["all"])
            pattern = Pattern(pid, spec["title"], severity, spec["description"], groups,
                              bool(spec.get("unsigned", False)))
        except (KeyError, ValueError, TypeError) as exc:
            raise PatternError(f"behavior {pid}: {exc}") from exc
        if not groups or not all(groups):
            raise PatternError(f"behavior {pid}: 'all' needs at least one non-empty group")
        for group in groups:
            for signal in group:
                _check_signal(pid, signal)
        patterns.append(pattern)
    return patterns


@cache
def patterns() -> tuple[Pattern, ...]:
    text = resources.files("unopened").joinpath("data/behaviors.toml").read_text("utf-8")
    return tuple(parse(tomllib.loads(text)))


def _signal_hit(signal: str, capa: set[str], finding_ids: set[str]) -> str | None:
    if signal.startswith("capa:"):
        name = signal[5:]
        return f"capa: {name}" if name in capa else None
    if signal.startswith("capa~"):
        text = signal[5:].lower()
        hit = next((c for c in sorted(capa) if text in c.lower()), None)
        return f"capa: {hit}" if hit else None
    if signal.startswith("finding:"):
        fid = signal[8:]
        return f"finding {fid}" if fid in finding_ids else None
    return None


def evaluate(results: list[AnalyzerResult],
             pattern_list: tuple[Pattern, ...] | None = None) -> AnalyzerResult:
    """One synthetic analyzer result holding a finding per matched pattern."""
    pattern_list = patterns() if pattern_list is None else pattern_list
    by_name = {r.name: r for r in results}
    finding_ids = {f.id for r in results for f in r.findings}
    capa_result = by_name.get("capa")
    capa = {c["name"] for c in (capa_result.data.get("capabilities", [])
                                if capa_result and capa_result.status == Status.OK else [])}
    sig = by_name.get("authenticode")
    signed_flag = (sig.data or {}).get("signed") if sig is not None else None
    unsigned = "sig.unsigned" in finding_ids
    signed = signed_flag is True

    out = AnalyzerResult(SOURCE, Status.OK, data={"matched": [], "blocked_by_signature": []})
    for p in pattern_list:
        evidence = []
        for group in p.groups:
            hit = next((h for s in group if (h := _signal_hit(s, capa, finding_ids))), None)
            if hit is None:
                break
            evidence.append(hit)
        else:
            severity, note = p.severity, "; not digitally signed" if p.unsigned else ""
            if p.unsigned and not unsigned:
                if not signed:
                    out.data["blocked_by_signature"].append(p.id)
                    continue
                # Signed: keep the evidence visible, but it no longer drives the verdict.
                severity = Severity.LOW
                note = ("; the file is signed, so this counts only as a lead (legitimate "
                        "signed tools do this too, and signatures can be stolen)")
            out.data["matched"].append({"id": p.id, "evidence": evidence,
                                        "severity": str(severity)})
            out.findings.append(Finding(
                f"behavior.{p.id}", severity, f"Behavior: {p.title}",
                f"{p.description} Evidence: {'; '.join(evidence)}{note}.", SOURCE,
            ))
    if out.data["blocked_by_signature"]:
        out.not_checked.append(
            "Behavior patterns that apply only to unsigned files ("
            + ", ".join(out.data["blocked_by_signature"])
            + ") matched, but the signature could not be checked, so they were not reported"
        )
    if capa_result is None or capa_result.status != Status.OK:
        if any(s.startswith("capa") for p in pattern_list for g in p.groups for s in g) \
                and by_name.get("pe") and by_name["pe"].status != Status.NOT_APPLICABLE:
            out.not_checked.append("Behavior patterns that rely on capa (capa did not run)")
    return out
