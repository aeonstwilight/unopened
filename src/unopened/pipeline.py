"""Triage pipeline: identify, run every applicable analyzer, triage extracted members
recursively, apply the verdict rules, and assemble one Report.

Extracted members live in one private temporary directory per top-level triage, which
is deleted when triage returns, whether it succeeded or not.
"""

from __future__ import annotations

import itertools
import shutil
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__, behaviors
from .analyzers import Context, Options, registry
from .analyzers.strings import summarize_indicators
from .extraction import Budget, basename
from .identify import identify
from .indicators.collect import IndicatorSet
from .indicators.extract import Hit
from .model import (
    INCOMPLETE_STATUSES,
    AnalyzerResult,
    FileType,
    Finding,
    NotChecked,
    Report,
    Severity,
    Status,
)
from .runner import run_analyzer
from .verdict import evaluate

# Checks the project will do but this version does not, by file kind. Listed under
# "Not checked" so that an absent check is never mistaken for a clean result.
ALWAYS_PLANNED = [
    ("Decoded and stack strings (FLOSS)", "not run; only plain ASCII/UTF-16LE strings were read"),
]
REPUTATION_OFF = NotChecked(
    "Hash reputation lookup",
    "off; rerun with --reputation to look up the SHA256 at MalwareBazaar and VirusTotal "
    "(only the hash is sent)",
)
PLANNED_BY_KIND: dict[str, list[tuple[str, str]]] = {
    "ooxml": [
        ("Content of the document's compressed parts",
         "strings were read from the compressed bytes; only macros, relationships, field "
         "codes and embedded objects were extracted"),
        ("Files embedded in Office documents", "listed, not extracted or analyzed"),
    ],
    "ole": [("Files embedded in Office documents", "listed, not extracted or analyzed")],
    "zip": [("Strings inside compressed members",
             "the archive's own strings are compressed bytes; members are analyzed separately")],
    "mz": [("PE analysis", "the file starts with MZ but has no valid PE header")],
    "unknown": [("Type-specific analysis", "file type not recognized; only hashes, strings "
                 "and YARA were checked")],
}
EXTRACTING_KINDS = {"zip", "7z", "iso", "pdf"}
# M5 holdout: two MSI installers came back "no findings" without the report saying their
# contents were never examined.
MSI_NOT_CHECKED = "Windows Installer (MSI) contents"
MSI_REASON = ("custom actions, embedded scripts and packaged files are not analyzed in "
              "version 1; only hashes, strings and YARA were checked")
MEMBER_SOURCES = ("archive", "pdf")
RUNNABLE_MEMBER_KINDS = {"pe", "mz", "lnk", "script"}


class _Session:
    """State shared by one top-level triage and all its nested members."""

    def __init__(self, options: Options, isolate: bool):
        self.options = options
        self.isolate = isolate
        self.budget = Budget.from_limits(options.limits)
        self.workdir = Path(tempfile.mkdtemp(prefix="unopened-"))  # mode 0700
        self.counter = itertools.count(1)
        self.deadline = time.monotonic() + options.file_timeout

    def time_left(self) -> float:
        return self.deadline - time.monotonic()

    def new_extract_dir(self) -> Path:
        d = self.workdir / f"x{next(self.counter):04d}"
        d.mkdir(mode=0o700)
        return d


def triage(path: Path, options: Options, *, isolate: bool = True,
           transport: Any = None, env: dict[str, str] | None = None) -> Report:
    """Triage one file. `transport` and `env` replace the HTTP client and environment
    for reputation lookups (used by tests)."""
    session = _Session(options, isolate)
    try:
        report = _triage(session, path, name=path.name, depth=0)
    finally:
        shutil.rmtree(session.workdir, ignore_errors=True)
    if options.reputation:
        add_reputation(report, options, transport, env)
    if options.hunt:
        from .hunt import build

        report.hunt = build(report, options.hunt_days)
    return report


def add_reputation(report: Report, options: Options, transport: Any = None,
                   env: dict[str, str] | None = None) -> None:
    """Look up the file's and its members' SHA256 hashes, then re-apply the verdict rules
    bottom-up so members' reputation reaches their containers."""
    from .reputation import lookup_all

    reports = list(walk(report))
    hashes = [r.hashes["sha256"] for r in reports if r.hashes.get("sha256")]
    results = lookup_all(hashes, options.max_lookups, send=transport, env=env)
    for r in reports:
        sha = r.hashes.get("sha256")
        rep = results.get(sha) if sha else None
        if rep is None:
            rep = {"enabled": True, "skipped": "no SHA256 to look up", "sources": {}}
        r.reputation = rep
        if rep.get("skipped"):
            r.not_checked.append(NotChecked("Hash reputation lookup", rep["skipped"]))
        for name, res in rep["sources"].items():
            if res["status"] in ("skipped", "error", "rate_limited"):
                r.not_checked.append(NotChecked(f"Reputation: {name}",
                                                f"{res['status']}: {res['detail']}"))
    _reevaluate(report)


def _reevaluate(report: Report) -> None:
    for child in report.children:
        _reevaluate(child["report"])
    report.verdict = evaluate(report)


def _triage(session: _Session, path: Path, *, name: str, depth: int) -> Report:
    options = session.options
    size = path.stat().st_size
    extra_results: list[AnalyzerResult] = []
    try:
        file_type = identify(path, name=name)
    except Exception as exc:
        file_type = FileType("unknown", "Type identification failed")
        extra_results.append(AnalyzerResult(
            "identify", Status.ERROR, f"{type(exc).__name__}: {exc}"
        ))
    extract_dir = None
    if file_type.kind in EXTRACTING_KINDS and depth < options.limits.max_depth:
        extract_dir = session.new_extract_dir()
    ctx = Context(path=path, file_type=file_type, options=options, size=size, depth=depth,
                  extract_dir=extract_dir, files_left=session.budget.files_left,
                  bytes_left=session.budget.bytes_left)
    analyzers = registry()
    results = extra_results + [
        run_analyzer(a, ctx, isolate=session.isolate, time_left=session.time_left())
        for a in analyzers
    ]
    titles = {a.name: a.title for a in analyzers} | {"identify": "File type identification"}
    by_name = {r.name: r for r in results}

    # Charge what the analyzers extracted to the shared budget.
    for source in MEMBER_SOURCES:
        if (r := by_name.get(source)) and r.status in (Status.OK, Status.PARTIAL):
            session.budget.files_left -= r.data.get("extracted_files", 0)
            session.budget.bytes_left -= r.data.get("extracted_bytes", 0)

    children: list[dict[str, Any]] = []
    for source in MEMBER_SOURCES:
        r = by_name.get(source)
        if r is None or r.status not in (Status.OK, Status.PARTIAL) or extract_dir is None:
            continue
        stored_members = [m for m in r.data.get("members", []) if m.get("stored")]
        for i, member in enumerate(stored_members):
            stored = extract_dir / member["stored"]
            if session.time_left() <= 0:
                rest = stored_members[i:]
                r.data["members_not_analyzed"] = [m["name"] for m in rest]
                r.not_checked.append(
                    f"{len(rest)} of {len(stored_members)} extracted member(s) were not "
                    f"analyzed: the {options.file_timeout:g}-second time budget for this file "
                    f"was used up (first: {', '.join(m['name'] for m in rest[:3])})")
                break
            child = _triage(session, stored, name=basename(member["name"]), depth=depth + 1)
            child.file_name = member["name"]
            children.append({"source": source, "member": member, "report": child})
            stored.unlink(missing_ok=True)

    hashes: dict[str, str] = {}
    if (r := by_name.get("hashes")) and r.status == Status.OK:
        hashes.update(r.data)
    if (r := by_name.get("pe")) and r.data.get("imphash"):
        hashes["imphash"] = r.data["imphash"]
    if (r := by_name.get("tlsh")) and r.data.get("tlsh"):
        hashes["tlsh"] = r.data["tlsh"]

    found = IndicatorSet(options.allowlist, options.max_indicators)
    if r := by_name.get("strings"):
        found.merge(r.data.pop("indicators", []), r.data.pop("allowlisted", []))
    for r in results:
        for source, text in r.data.pop("indicator_texts", []):
            found.add_text(text, source=source)
        for d in r.data.pop("direct_indicators", []):
            found.add(Hit(d["kind"], d["value"], tuple(d.get("tags", ()))), source=r.name,
                      context=d.get("context", ""))
    for child in children:
        label = f"member {child['member']['name']}"
        found.merge([dict(e, sources=[f"{label}: {s}" for s in e["sources"]])
                     for e in child["report"].indicators], [])
    indicators = found.entries()
    if (r := by_name.get("strings")) and r.status in (Status.OK, Status.PARTIAL):
        r.findings += [
            Finding(f.id, f.severity, f.title, f.detail, "indicators")
            for f in summarize_indicators(indicators)
        ]
    if children:
        source = next(s for s in MEMBER_SOURCES if s in by_name and any(
            c["source"] == s for c in children))
        by_name[source].findings += container_findings(children)

    temper_for_valid_signature(results)
    # Combinations of signals across analyzers (data/behaviors.toml).
    results.append(behaviors.evaluate(results))
    titles["behavior"] = "Behavior patterns (combinations of signals)"

    report = Report(
        tool_version=__version__,
        generated_at=datetime.now(UTC).replace(microsecond=0).isoformat(),
        file_name=name,
        file_size=size,
        file_type=file_type,
        hashes=hashes,
        results=results,
        indicators=indicators,
        allowlisted_counts=found.allowlisted_counts(),
        not_checked=build_not_checked(file_type, results, titles) + _reputation_note(options),
        verdict={},
        depth=depth,
        children=children,
    )
    report.verdict = evaluate(report)
    return report


SIGNED_YARA_NOTE = (
    " The file carries a valid Authenticode signature, so this single rule match is "
    "rated MEDIUM rather than HIGH: in M5 validation, YARA rules matched signed Microsoft "
    "tools. Review the rule; a valid signature is not proof of safety, since signing "
    "certificates are sometimes stolen."
)


SIGNED_PACKING_NOTE = (
    " The file carries a valid Authenticode signature: publishers sign packed and "
    "self-extracting builds routinely (M5 corpus 2: Rufus, a UPX-packed tool signed by its "
    "developer), so packing on a signed file is rated LOW. A valid signature is not proof "
    "of safety."
)
PACKING_FINDINGS = {"pe.packer_section", "pe.wx_section", "pe.high_entropy_section"}


def temper_for_valid_signature(results: list[AnalyzerResult]) -> None:
    """On a validly signed file, a lone HIGH YARA match becomes MEDIUM and packing
    findings become LOW, each with a note. Other evidence, including behavior patterns,
    is unchanged."""
    sig = next((r for r in results if r.name == "authenticode"), None)
    if sig is None or not (sig.data or {}).get("valid"):
        return
    for r in results:
        for i, f in enumerate(r.findings):
            if r.name == "yara" and f.id == "yara.match" and f.severity == Severity.HIGH:
                r.findings[i] = Finding(f.id, Severity.MEDIUM, f.title,
                                        f.detail + SIGNED_YARA_NOTE, f.source)
            elif (r.name == "pe" and f.id in PACKING_FINDINGS
                  and f.severity in (Severity.HIGH, Severity.MEDIUM)):
                r.findings[i] = Finding(f.id, Severity.LOW, f.title,
                                        f.detail + SIGNED_PACKING_NOTE, f.source)


def container_findings(children: list[dict[str, Any]]) -> list[Finding]:
    """Findings about what an archive, disk image or PDF carries, known only after its
    members have been identified."""
    findings: list[Finding] = []
    kinds = {id(c): c["report"].file_type.kind if c["report"].file_type else "" for c in children}
    runnable = [c for c in children if kinds[id(c)] in RUNNABLE_MEMBER_KINDS]
    if runnable:
        names = ", ".join(c["member"]["name"] for c in runnable[:5])
        findings.append(Finding(
            "container.runnable_member", Severity.MEDIUM,
            f"Contains programs, shortcuts or scripts ({len(runnable)})",
            f"{names}. Delivering these inside an archive or image is a common way past "
            "mail filters.", "container",
        ))
    lnks = [c for c in runnable if kinds[id(c)] == "lnk"]
    hidden = [c for c in children if c["member"].get("hidden")]
    if lnks and hidden:
        findings.append(Finding(
            "container.lnk_with_hidden_files", Severity.HIGH,
            "Shortcut shown next to hidden files",
            "The classic disk-image lure: the user sees only a shortcut, which runs the hidden "
            f"payload ({', '.join(c['member']['name'] for c in hidden[:5])}).", "container",
        ))
    disguised = [c for c in children if c["report"].file_type
                 and any(m.severity == Severity.HIGH for m in c["report"].file_type.mismatches)]
    if disguised:
        findings.append(Finding(
            "container.deceptive_member", Severity.HIGH,
            "Member disguised as a different file type",
            ", ".join(c["member"]["name"] for c in disguised[:5])
            + ". See the member's section for details.", "container",
        ))
    return findings


def build_not_checked(
    file_type: FileType, results: list[AnalyzerResult], titles: dict[str, str]
) -> list[NotChecked]:
    items: list[NotChecked] = []
    for r in results:
        title = titles.get(r.name, r.name)
        if r.status in INCOMPLETE_STATUSES:
            if r.status == Status.PARTIAL:
                for err in r.errors:
                    items.append(NotChecked(f"{title}: part", f"failed to parse: {err}"))
            else:
                items.append(NotChecked(title, f"{r.status}: {r.message}"))
        for note in r.not_checked:
            items.append(NotChecked(title, note))
    for check, reason in PLANNED_BY_KIND.get(file_type.kind, []) + ALWAYS_PLANNED:
        items.append(NotChecked(check, reason))
    if file_type.kind == "ole" and file_type.subtype == "msi":
        items.append(NotChecked(MSI_NOT_CHECKED, MSI_REASON))
    return items


def _reputation_note(options: Options) -> list[NotChecked]:
    return [] if options.reputation else [REPUTATION_OFF]


def walk(report: Report):
    """The report and every nested member report, depth first."""
    yield report
    for child in report.children:
        yield from walk(child["report"])
