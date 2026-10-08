"""Full results as JSON.

Every string is defanged except values under a key named "raw", which carry the
original indicator (and file name) for machine use.
"""

from __future__ import annotations

import json
from typing import Any

from ..indicators.defang import defang_tree
from ..model import Report

SCHEMA_VERSION = 2


def to_dict(report: Report) -> dict[str, Any]:
    return defang_tree(_raw(report))


def _raw(report: Report) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "unopened", "version": report.tool_version},
        "generated_at": report.generated_at,
        "analysis": "static only; the sample was never executed",
        "file": {
            "name": report.file_name,
            "size": report.file_size,
            "raw": {"name": report.file_name},
        },
        "identification": report.file_type.to_dict() if report.file_type else None,
        "hashes": report.hashes,
        "verdict": report.verdict,
        "findings": [f.to_dict() for f in report.findings()],
        "indicators": report.indicators,
        "allowlisted_counts": report.allowlisted_counts,
        "analyzers": {r.name: r.to_dict() for r in report.results},
        "not_checked": [{"check": n.check, "reason": n.reason} for n in report.not_checked],
        "reputation": report.reputation,
        "hunt": ({"days": report.hunt["days"], "truncated": report.hunt["truncated"],
                  "raw": {"queries": report.hunt["platforms"],
                          "values": report.hunt["values"]}} if report.hunt else None),
        "members": [
            {"source": c["source"], "member": _member(c["member"]), "report": _raw(c["report"])}
            for c in report.children
        ],
    }


def _member(m: dict[str, Any]) -> dict[str, Any]:
    # The original member name may itself be an indicator; keep it raw only under "raw".
    return {**m, "raw": {"name": m["name"]}}


def render(report: Report) -> str:
    return json.dumps(to_dict(report), indent=2, ensure_ascii=False) + "\n"
