"""Capabilities with capa, mapped to MITRE ATT&CK and MBC.

capa disassembles the file with vivisect (or reads .NET metadata with dnfile). Some
vivisect analysis passes emulate instructions inside a pure-Python emulator to recover
things like call arguments; nothing is executed natively and the sample is never
loaded by the operating system. The rules directory comes from the user.
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from typing import Any

from ..model import AnalyzerOutput, Finding, Severity
from . import AnalyzerUnavailable, Context

ATTACK_ID = re.compile(r"\[(T\d{4}(?:\.\d{3})?)\]")
MBC_ID = re.compile(r"\[([A-Z]\d{4}(?:\.[A-Z0-9]{3,4})?)\]")

# ATT&CK tactics listed first in the report. Every tactic summary is LOW: during M5
# validation, Defense Evasion, Persistence and Privilege Escalation summaries appeared on
# nearly every signed admin tool, and at MEDIUM three of them alone made a benign file
# "suspicious". Specific capabilities carry weight through behavior patterns instead
# (data/behaviors.toml).
NOTABLE_TACTICS = {
    "Defense Evasion", "Persistence", "Privilege Escalation", "Credential Access",
    "Collection", "Impact", "Command and Control", "Exfiltration", "Lateral Movement",
}
QUIET_LOGGERS = ("capa", "vivisect", "envi", "vtrace", "viv_utils", "dnfile", "dncil")


def _parse_attack(entries: list[str]) -> list[dict[str, str]]:
    parsed = []
    for entry in entries:
        parts = [p.strip() for p in entry.split("::")]
        m = ATTACK_ID.search(entry)
        parsed.append({
            "tactic": parts[0] if parts else "",
            "technique": re.sub(r"\s*\[.*\]$", "", "::".join(parts[1:])),
            "id": m.group(1) if m else "",
        })
    return parsed


def analyze_capa(ctx: Context) -> AnalyzerOutput:
    rules_path = ctx.options.capa_rules
    if rules_path is None:
        raise AnalyzerUnavailable(
            "no capa rules configured; pass --capa-rules DIR or set UNOPENED_CAPA_RULES "
            "(capa's pip package does not include rules)"
        )
    if not rules_path.exists():
        raise AnalyzerUnavailable(f"capa rules path {rules_path} does not exist")

    for name in QUIET_LOGGERS:
        logging.getLogger(name).setLevel(logging.ERROR)
    import capa.capabilities.common as capabilities
    import capa.helpers
    import capa.loader
    import capa.rules
    import capa.rules.cache  # noqa: F401  (get_rules needs it imported)

    rules = capa.rules.get_rules([rules_path], enable_cache=False)
    fmt = capa.helpers.get_auto_format(ctx.path)
    if fmt not in (capa.loader.FORMAT_PE, capa.loader.FORMAT_DOTNET):
        raise ValueError(f"capa does not support this file's format ({fmt})")
    is_dotnet = fmt == capa.loader.FORMAT_DOTNET
    backend = capa.loader.BACKEND_DOTNET if is_dotnet else capa.loader.BACKEND_VIV
    sig_dir = ctx.options.capa_signatures
    sigs = capa.loader.get_signatures(sig_dir) if sig_dir else []
    extractor = capa.loader.get_extractor(
        ctx.path, fmt, capa.loader.OS_AUTO, backend, sigs,
        should_save_workspace=False, disable_progress=True,
    )
    result = capabilities.find_capabilities(rules, extractor, disable_progress=True)

    found: list[dict[str, Any]] = []
    limitations: list[dict[str, str]] = []
    for name, matches in result.matches.items():
        rule = rules.rules[name]
        # internal/limitation/static (capa 9) or internal/limitation/file (older rule sets)
        if str(rule.meta.get("namespace", "")).startswith("internal/limitation/"):
            limitations.append({"rule": name, "description": rule.meta.get("description", "")})
            continue
        if rule.meta.get("lib") or rule.is_subscope_rule() \
                or str(rule.meta.get("namespace", "")).startswith("internal/"):
            continue
        found.append({
            "name": name,
            "namespace": rule.meta.get("namespace", ""),
            "attack": _parse_attack(rule.meta.get("att&ck", []) or []),
            "mbc": list(rule.meta.get("mbc", []) or []),
            "matches": len(matches),
        })
    found.sort(key=lambda c: (c["namespace"], c["name"]))

    out = AnalyzerOutput(data={
        "rules_path": str(rules_path),
        "rule_count": len(rules.rules),
        "format": fmt,
        "backend": backend,
        "signatures": bool(sigs),
        "capabilities": found,
        "limitations": limitations,
    })
    _findings(found, limitations, out)
    return out


def _findings(found: list[dict[str, Any]], limitations: list[dict[str, str]],
              out: AnalyzerOutput) -> None:
    for lim in limitations:
        out.findings.append(Finding(
            "capa.limited",
            # INFO: this says what could not be seen, not what the file does. It is listed
            # under Not checked; as MEDIUM it stacked toward "suspicious" on every .NET
            # assembly and installer (M5 corpus 2).
            Severity.INFO, "capa results are limited for this file",
            f"{lim['description'] or lim['rule']}. Packed, installer or otherwise wrapped "
            "files hide their real code from static analysis, so few capabilities show.",
        ))
        out.not_checked.append(f"Capabilities hidden by packing or wrapping ({lim['rule']})")
    by_tactic: dict[str, set[str]] = defaultdict(set)
    for cap in found:
        for a in cap["attack"]:
            by_tactic[a["tactic"]].add(cap["name"])
    for tactic in sorted(by_tactic, key=lambda t: (t not in NOTABLE_TACTICS, t)):
        names = sorted(by_tactic[tactic])
        techniques = sorted({a["id"] for c in found for a in c["attack"]
                             if a["tactic"] == tactic and a["id"]})
        out.findings.append(Finding(
            f"capa.tactic.{tactic.lower().replace(' ', '_')}",
            Severity.LOW,
            f"capa: {tactic} ({len(names)} capabilit{'y' if len(names) == 1 else 'ies'})",
            f"{'; '.join(names)}. ATT&CK: {', '.join(techniques) or 'none'}. These are "
            "inferred from code patterns, not observed behavior.",
        ))
    if found:
        out.findings.append(Finding(
            "capa.summary",
            Severity.INFO, f"capa identified {len(found)} capabilit"
                           f"{'y' if len(found) == 1 else 'ies'}",
            "See the Capabilities section for the full list.",
        ))
    elif not limitations:
        out.findings.append(Finding(
            "capa.none",
            Severity.INFO, "capa found no capabilities",
            "None of the configured rules matched. This depends on the rules supplied.",
        ))
