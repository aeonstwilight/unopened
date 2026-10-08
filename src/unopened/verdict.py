"""Verdict rules: transparent, ordered, documented. No model, no scores.

Each rule has an ID, the verdict and confidence it produces, and a plain description.
Rules are checked in order; the first that matches sets the verdict. Every rule that
matches is listed in the report as a reason, with the findings that triggered it.

Verdicts, from most to least severe: malicious, suspicious, could not analyze,
no findings. "No findings" means only that the checks that ran found nothing at
MEDIUM or above. It is never a statement that the file is safe.

docs/verdict-rules.md is generated from this table (see render_markdown) and a test
keeps the two in sync.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .model import INCOMPLETE_STATUSES, Finding, Report, Severity, Status

MALICIOUS, SUSPICIOUS, COULD_NOT, NO_FINDINGS = (
    "malicious", "suspicious", "could not analyze", "no findings")
VERDICT_ORDER = {MALICIOUS: 0, SUSPICIOUS: 1, COULD_NOT: 2, NO_FINDINGS: 3}
CONFIDENCE_ORDER = ["low", "medium", "high"]

# The analyzer whose failure means the file's type was not really examined.
TYPE_ANALYZER = {
    "pe": "pe", "ole": "office", "ooxml": "office", "lnk": "lnk", "script": "script",
    "pdf": "pdf", "zip": "archive", "7z": "archive", "iso": "archive",
}
# Optional rule-based analyzers; when they did not run, "no findings" confidence drops.
RULE_ANALYZERS = {"yara"}
PE_RULE_ANALYZERS = {"capa"}


@dataclass
class Facts:
    report: Report
    findings: list[Finding]
    children: list[dict[str, Any]] = field(default_factory=list)

    def with_id(self, *ids: str) -> list[Finding]:
        return [f for f in self.findings
                if f.id in ids or any(i.endswith(".") and f.id.startswith(i) for i in ids)]

    def at(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def status(self, analyzer: str) -> Status | None:
        r = self.report.result(analyzer)
        return r.status if r else None

    def lnk_has_url(self) -> bool:
        return any(i["type"] == "url" and "lnk" in i.get("sources", [])
                   for i in self.report.indicators)


Evidence = list[str]


@dataclass(frozen=True)
class Rule:
    id: str
    verdict: str
    confidence: str
    description: str
    test: Callable[[Facts], Evidence | None]


def _titles(findings: list[Finding]) -> Evidence | None:
    return [f.title for f in findings] or None


def _all(*groups: list[Finding]) -> Evidence | None:
    if all(groups):
        return [f.title for g in groups for f in g]
    return None


VT_MALICIOUS_THRESHOLD = 5


def _rep(f: Facts, source: str) -> dict[str, Any] | None:
    rep = f.report.reputation or {}
    res = (rep.get("sources") or {}).get(source)
    return res if res and res["status"] == "found" else None


def _mb_known(f: Facts) -> Evidence | None:
    res = _rep(f, "malwarebazaar")
    if res is None:
        return None
    d = res["data"]
    family = f" as {d['signature']}" if d.get("signature") else ""
    return [f"MalwareBazaar lists this hash{family} (first seen {d.get('first_seen')})"]


def _vt_count(f: Facts) -> int | None:
    res = _rep(f, "virustotal")
    return res["data"].get("malicious", 0) if res else None


def _vt_many(f: Facts) -> Evidence | None:
    n = _vt_count(f)
    if n is not None and n >= VT_MALICIOUS_THRESHOLD:
        return [f"VirusTotal: {n} engines report it malicious"]
    return None


def _vt_few(f: Facts) -> Evidence | None:
    n = _vt_count(f)
    if n is not None and 0 < n < VT_MALICIOUS_THRESHOLD:
        return [f"VirusTotal: {n} engine(s) report it malicious"]
    return None


def _yara_high(f: Facts) -> Evidence | None:
    return _titles([x for x in f.with_id("yara.match") if x.severity == Severity.HIGH])


def _macro_autoexec(f: Facts) -> Evidence | None:
    return _all(f.with_id("office.autoexec"), f.with_id("office.suspicious_keywords"))


def _lnk_lolbin_command(f: Facts) -> Evidence | None:
    target = [x for x in f.with_id("lnk.lolbin_target", "lnk.lolbin_argument")
              if x.severity == Severity.HIGH]
    command = f.with_id("lnk.encoded_powershell", "lnk.hidden_window", "lnk.padded_arguments",
                        "lnk.appended_pe")
    if target and (command or f.lnk_has_url()):
        return [x.title for x in target + command] + (
            ["shortcut arguments contain a URL"] if f.lnk_has_url() else [])
    return None


def _children(verdict: str) -> Callable[[Facts], Evidence | None]:
    def test(f: Facts) -> Evidence | None:
        hits = [c for c in f.children if c["report"].verdict["value"] == verdict]
        return [f"{c['member']['name']}: {verdict} ({c['report'].verdict['confidence']})"
                for c in hits] or None
    return test


def _two_high(f: Facts) -> Evidence | None:
    high = f.at(Severity.HIGH)
    if len({x.source for x in high}) >= 2:
        return [x.title for x in high]
    return None


def _three_medium(f: Facts) -> Evidence | None:
    medium = f.at(Severity.MEDIUM)
    return [x.title for x in medium] if len(medium) >= 3 else None


def _obfuscated_runner(f: Facts) -> Evidence | None:
    obfuscated = f.with_id("script.obfuscated")
    r = f.report.result("script")
    if not obfuscated or r is None:
        return None
    runs = [k for k in r.data.get("keywords", []) if "execute" in k.get("tags", [])]
    if runs:
        return [x.title for x in obfuscated] + [k["title"] for k in runs]
    return None


def _type_analyzer_failed(f: Facts) -> Evidence | None:
    ft = f.report.file_type
    name = TYPE_ANALYZER.get(ft.kind) if ft else None
    if name is None:
        return None
    r = f.report.result(name)
    if r is not None and r.status in (Status.ERROR, Status.TIMEOUT, Status.UNAVAILABLE):
        return [f"{name} analyzer {r.status}: {r.message}"]
    return None


def _nothing_extracted(f: Facts) -> Evidence | None:
    r = f.report.result("archive")
    if r is None or r.status not in (Status.OK, Status.PARTIAL):
        return None
    members = r.data.get("members", [])
    if members and not any(m.get("stored") for m in members):
        reasons = sorted({m["skipped"] for m in members if m.get("skipped")})
        return [f"none of {len(members)} member(s) could be analyzed"] + reasons[:3]
    return None


def _unknown_password(f: Facts) -> Evidence | None:
    return _titles(f.with_id("archive.password_unknown", "pdf.encrypted", "office.encrypted"))


RULES: list[Rule] = [
    Rule("V-MAL-01", MALICIOUS, "high",
         "A configured YARA rule with severity high (or score 75 and above) matched.",
         _yara_high),
    Rule("V-REP-01", MALICIOUS, "high",
         "MalwareBazaar (a database of known malware samples) has this exact hash. "
         "Needs --reputation.", _mb_known),
    Rule("V-REP-02", MALICIOUS, "high",
         f"VirusTotal reports {VT_MALICIOUS_THRESHOLD} or more engines detecting this hash as "
         "malicious. Needs --reputation and VT_API_KEY.", _vt_many),
    Rule("V-MAL-02", MALICIOUS, "high",
         "Office macros run automatically on open and use functions that run programs, "
         "download files or create objects.", _macro_autoexec),
    Rule("V-MAL-03", MALICIOUS, "high",
         "A shortcut launches a scripting or download tool (LOLBin) with an encoded, hidden, "
         "padded or URL-bearing command, or carries an appended program.", _lnk_lolbin_command),
    Rule("V-MAL-04", MALICIOUS, "high",
         "A document contains a DDE field that can run a command.",
         lambda f: _titles(f.with_id("office.dde"))),
    Rule("V-MAL-05", MALICIOUS, "high",
         "A document loads a remote template or object when opened (template injection).",
         lambda f: _titles(f.with_id("office.remote_load"))),
    Rule("V-MAL-06", MALICIOUS, "high",
         "A document or PDF embeds a file with an executable extension.",
         lambda f: _titles(f.with_id("office.embedded_executable", "pdf.embedded_executable"))),
    Rule("V-MAL-07", MALICIOUS, "high",
         "A script (or PDF JavaScript) both downloads content and runs code, after "
         "deobfuscation.", lambda f: _titles(f.with_id("script.download_execute",
                                                         "pdf.download_execute"))),
    Rule("V-MAL-08", MALICIOUS, "high",
         "A PDF contains a Launch action that can start a program.",
         lambda f: _titles(f.with_id("pdf.launch"))),
    Rule("V-MAL-09", MALICIOUS, "medium",
         "A member of this archive, disk image or PDF was judged malicious.",
         _children(MALICIOUS)),
    Rule("V-MAL-10", MALICIOUS, "medium",
         "Two or more HIGH findings from different analyzers.", _two_high),
    Rule("V-SUS-01", SUSPICIOUS, "medium",
         "At least one HIGH finding.", lambda f: _titles(f.at(Severity.HIGH))),
    Rule("V-SUS-02", SUSPICIOUS, "medium",
         "A member of this archive, disk image or PDF was judged suspicious.",
         _children(SUSPICIOUS)),
    Rule("V-REP-03", SUSPICIOUS, "low",
         f"VirusTotal reports between 1 and {VT_MALICIOUS_THRESHOLD - 1} engines detecting this "
         "hash as malicious (few detections are often false positives).", _vt_few),
    Rule("V-SUS-03", SUSPICIOUS, "medium",
         "An obfuscated script that also runs programs or code.", _obfuscated_runner),
    Rule("V-SUS-04", SUSPICIOUS, "low",
         "Three or more MEDIUM findings.", _three_medium),
    Rule("V-CNA-01", COULD_NOT, "high",
         "The analyzer for this file type failed, timed out or is not installed, so the "
         "file was not really examined.", _type_analyzer_failed),
    Rule("V-CNA-02", COULD_NOT, "high",
         "Encrypted content could not be opened with the configured passwords.",
         _unknown_password),
    Rule("V-CNA-03", COULD_NOT, "high",
         "None of the archive's members could be extracted (limits, encryption or damage).",
         _nothing_extracted),
    Rule("V-CNA-04", COULD_NOT, "medium",
         "A member of this archive, disk image or PDF could not be analyzed.",
         _children(COULD_NOT)),
    Rule("V-NF-01", NO_FINDINGS, "medium",
         "No rule above matched: nothing at MEDIUM or above, or not enough to call it "
         "suspicious. This is not a statement that the file is safe.",
         lambda f: ["no rule above matched"]),
]


def _lower(confidence: str) -> str:
    return CONFIDENCE_ORDER[max(0, CONFIDENCE_ORDER.index(confidence) - 1)]


def evaluate(report: Report) -> dict[str, Any]:
    facts = Facts(report, report.findings(), getattr(report, "children", []))
    reasons = []
    for rule in RULES:
        evidence = rule.test(facts)
        if evidence:
            reasons.append({"rule": rule.id, "verdict": rule.verdict,
                            "description": rule.description, "evidence": evidence[:10]})
    first = next(r for r in RULES if r.id == reasons[0]["rule"])
    verdict, confidence = first.verdict, first.confidence
    caveats = []

    incomplete = [r for r in report.results if r.status in INCOMPLETE_STATUSES]
    if verdict == NO_FINDINGS:
        wanted = set(RULE_ANALYZERS)
        if report.file_type and report.file_type.kind == "pe":
            wanted |= PE_RULE_ANALYZERS
        missing = sorted(r.name for r in report.results
                         if r.name in wanted and r.status != Status.OK)
        if incomplete or missing:
            confidence = "low"
            caveats.append("lowered: " + ", ".join(
                [f"{r.name} {r.status}" for r in incomplete]
                + [f"{m} did not run" for m in missing if m not in {r.name for r in incomplete}]))
        rep = report.reputation
        if rep is not None:
            answered = [s for s, r in (rep.get("sources") or {}).items()
                        if r["status"] in ("found", "not_found")]
            if not answered:
                confidence = "low"
                caveats.append("lowered: reputation lookup was requested but no source answered")
        if report.file_type and report.file_type.kind == "empty":
            confidence = "low"
            caveats.append("lowered: the file is empty")
    elif incomplete and verdict in (MALICIOUS, SUSPICIOUS):
        caveats.append("note: some checks did not complete ("
                       + ", ".join(f"{r.name} {r.status}" for r in incomplete)
                       + "); the evidence above still stands")
    if verdict != COULD_NOT and any(
            c["report"].verdict["value"] == COULD_NOT for c in facts.children) \
            and verdict == NO_FINDINGS:
        confidence = "low"

    return {
        "value": verdict,
        "confidence": confidence,
        "rule": first.id,
        "reasons": [r for r in reasons if r["rule"] != "V-NF-01" or verdict == NO_FINDINGS],
        "caveats": caveats,
        "note": "Produced by fixed, documented rules (verdict-rules in the project's docs "
                "folder), not by a model. Every verdict lists its reasons; see Not checked for "
                "what was not examined.",
    }


def render_markdown() -> str:
    lines = [
        "# Verdict rules",
        "",
        "<!-- Generated from src/unopened/verdict.py by `python -m unopened.verdict`. "
        "Do not edit by hand; tests/test_verdict.py checks it is in sync. -->",
        "",
        "Rules are checked in order. The first rule that matches sets the verdict and its "
        "confidence; every rule that matches is listed as a reason in the report, with the "
        "findings that triggered it.",
        "",
        "Verdicts, most to least severe: **malicious**, **suspicious**, **could not "
        "analyze**, **no findings**. \"No findings\" only means that the checks that ran "
        "found nothing at MEDIUM or above; it never means the file is safe.",
        "",
        "| Rule | Verdict | Confidence | When it matches |",
        "|---|---|---|---|",
    ]
    lines += [f"| {r.id} | {r.verdict} | {r.confidence} | {r.description} |" for r in RULES]
    lines += [
        "",
        "## Confidence adjustments",
        "",
        "- **No findings** drops to *low* confidence when any analyzer was partial, failed, "
        "timed out or was unavailable, when YARA did not run (no rules configured), when "
        "capa did not run on a PE file, when a member could not be analyzed, or when the "
        "file is empty.",
        "- With `--reputation`, **no findings** also drops to *low* when no reputation source "
        "answered. A hash that no source knows is unknown, never clean, and never changes the "
        "verdict.",
        "- **Malicious** and **suspicious** keep their confidence when other checks are "
        "incomplete (the evidence found still stands) but the report notes the gaps.",
        "- Archives, disk images and PDFs take the most severe verdict among their own "
        "findings and their members (V-MAL-09, V-SUS-02, V-CNA-04).",
        "",
        "Finding IDs used by these rules (for example `office.autoexec`) are stable and "
        "appear in the JSON report next to every finding.",
        "",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    print(render_markdown(), end="")
