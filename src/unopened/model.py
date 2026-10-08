"""Data model shared by the pipeline, analyzers and report writers.

Everything here is plain data (dataclasses of str/int/float/list/dict) so results can
cross a process boundary and serialize to JSON without custom hooks.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class Status(StrEnum):
    """Outcome of one analyzer run. Anything other than OK or NOT_APPLICABLE means
    some check did not happen and the report must say so."""

    OK = "ok"
    PARTIAL = "partial"  # ran, but some parts failed; see errors
    ERROR = "error"  # crashed or could not parse
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"  # an optional library is not installed or failed to load
    NOT_APPLICABLE = "not_applicable"


INCOMPLETE_STATUSES = frozenset({Status.PARTIAL, Status.ERROR, Status.TIMEOUT, Status.UNAVAILABLE})


class Severity(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_ORDER = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2, Severity.INFO: 3}


@dataclass
class Finding:
    """One observation worth an analyst's attention, phrased in plain language.

    id is stable (e.g. "office.autoexec"); verdict rules match on it, never on titles."""

    id: str
    severity: Severity
    title: str
    detail: str = ""
    source: str = ""  # analyzer name, filled in by the runner

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AnalyzerOutput:
    """What an analyzer function returns. Non-fatal problems go in errors; the runner
    turns a non-empty errors list into Status.PARTIAL."""

    data: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    not_checked: list[str] = field(default_factory=list)


@dataclass
class AnalyzerResult:
    name: str
    status: Status
    message: str = ""
    duration_seconds: float = 0.0
    data: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    not_checked: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": str(self.status),
            "message": self.message,
            "duration_seconds": round(self.duration_seconds, 3),
            "errors": list(self.errors),
            "findings": [f.to_dict() for f in self.findings],
            "data": self.data,
        }


@dataclass
class Mismatch:
    """A disagreement between what the file name claims and what the content is."""

    id: str
    severity: Severity
    message: str


@dataclass
class FileType:
    kind: str  # pe, mz, ole, ooxml, zip, lnk, pdf, 7z, iso, script, text, empty, unknown
    description: str
    subtype: str = ""  # e.g. "dll", "powershell", "word"
    details: dict[str, Any] = field(default_factory=dict)
    mismatches: list[Mismatch] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "subtype": self.subtype,
            "description": self.description,
            "details": self.details,
            "mismatches": [
                {"id": m.id, "severity": str(m.severity), "message": m.message}
                for m in self.mismatches
            ],
        }


@dataclass
class NotChecked:
    check: str
    reason: str


@dataclass
class Report:
    tool_version: str
    generated_at: str
    file_name: str
    file_size: int
    file_type: FileType | None
    hashes: dict[str, str]
    results: list[AnalyzerResult]
    indicators: list[dict[str, Any]]
    allowlisted_counts: dict[str, int]
    not_checked: list[NotChecked]
    verdict: dict[str, Any]
    depth: int = 0
    # Extracted members triaged recursively: {"source", "member", "report"}.
    children: list[dict[str, Any]] = field(default_factory=list)
    # None: lookups were off. Otherwise {"enabled", "sources": {name: outcome}, ...}.
    reputation: dict[str, Any] | None = None
    # Hunt queries (top-level report only); None when disabled.
    hunt: dict[str, Any] | None = None

    def result(self, name: str) -> AnalyzerResult | None:
        for r in self.results:
            if r.name == name:
                return r
        return None

    def findings(self) -> list[Finding]:
        """All findings across analyzers, most severe first."""
        found: list[Finding] = []
        if self.file_type:
            found.extend(
                Finding(m.id, m.severity, "File name does not match content", m.message, "identify")
                for m in self.file_type.mismatches
            )
        for r in self.results:
            found.extend(r.findings)
        return sorted(found, key=lambda f: SEVERITY_ORDER[f.severity])
