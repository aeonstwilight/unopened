"""Every verdict rule, driven by synthetic reports, plus the docs-in-sync check."""

from __future__ import annotations

from pathlib import Path

import pytest

from unopened import verdict
from unopened.model import AnalyzerResult, FileType, Finding, Report, Severity, Status

DOCS = Path(__file__).resolve().parents[1] / "docs" / "verdict-rules.md"
H, M, L = Severity.HIGH, Severity.MEDIUM, Severity.LOW


def rep_block(spec):
    """{"malwarebazaar": "found"|"not_found"|"error", "virustotal": <malicious count>|status}"""
    sources = {}
    for name, value in spec.items():
        if isinstance(value, int):
            sources[name] = {"status": "found", "detail": "", "data": {"malicious": value}}
        else:
            sources[name] = {"status": value, "detail": "",
                             "data": {"signature": "FixtureFamily", "first_seen": "2024-01-01"}}
    return {"enabled": True, "sources": sources}


def report(kind="pe", findings=(), statuses=None, data=None, children=(), indicators=(),
           reputation=None):
    """findings: (id, severity, source) tuples. statuses: {analyzer: Status}."""
    statuses = {"yara": Status.OK, "capa": Status.OK, **(statuses or {})}
    by_source: dict[str, list[Finding]] = {}
    for fid, sev, source in findings:
        by_source.setdefault(source, []).append(Finding(fid, sev, fid, "", source))
    names = set(statuses) | set(by_source) | set(data or {})
    results = [AnalyzerResult(n, statuses.get(n, Status.OK), "msg",
                              findings=by_source.get(n, []), data=(data or {}).get(n, {}))
               for n in sorted(names)]
    r = Report("t", "t", "f", 1, FileType(kind, kind), {}, results, list(indicators), {}, [],
               {}, children=list(children),
               reputation=rep_block(reputation) if reputation is not None else None)
    r.verdict = verdict.evaluate(r)
    return r


def child(v, conf="high"):
    c = report()
    c.verdict = {"value": v, "confidence": conf}
    return {"source": "archive", "member": {"name": "m"}, "report": c}


CASES = [
    ("V-MAL-01", dict(findings=[("yara.match", H, "yara")])),
    ("V-REP-01", dict(reputation={"malwarebazaar": "found"})),
    ("V-REP-02", dict(reputation={"virustotal": 12})),
    ("V-MAL-02", dict(kind="ooxml", findings=[("office.autoexec", H, "office"),
                                              ("office.suspicious_keywords", M, "office")],
                      data={"office": {"suspicious": [{"keyword": "Shell"}]}})),
    ("V-MAL-03", dict(kind="lnk", findings=[("lnk.lolbin_target", H, "lnk"),
                                            ("lnk.encoded_powershell", H, "lnk")])),
    ("V-MAL-04", dict(kind="ooxml", findings=[("office.dde", H, "office")])),
    ("V-MAL-05", dict(kind="ooxml", findings=[("office.remote_load", H, "office")])),
    ("V-MAL-06", dict(kind="pdf", findings=[("pdf.embedded_executable", H, "pdf")])),
    ("V-MAL-07", dict(kind="script", findings=[("script.download_execute", H, "script")])),
    ("V-MAL-08", dict(kind="pdf", findings=[("pdf.launch", H, "pdf")])),
    ("V-MAL-11", dict(kind="html", findings=[("web.smuggling", H, "web")])),
    ("V-MAL-12", dict(kind="rtf", findings=[("rtf.equation_object", M, "rtf"),
                                            ("rtf.objupdate", M, "rtf")])),
    ("V-MAL-13", dict(kind="html", findings=[("web.credential_exfil", H, "web")])),
    ("V-MAL-09", dict(kind="zip", children=[child("malicious")])),
    ("V-MAL-10", dict(findings=[("pe.x", H, "pe"), ("identify.double_extension", H, "identify")])),
    ("V-SUS-01", dict(findings=[("pe.x", H, "pe")])),
    ("V-SUS-02", dict(kind="zip", children=[child("suspicious")])),
    ("V-REP-03", dict(reputation={"virustotal": 2})),
    ("V-SUS-03", dict(kind="script", findings=[("script.obfuscated", M, "script")],
                      data={"script": {"keywords": [{"title": "runs", "tags": ["execute"]}]}})),
    ("V-SUS-04", dict(findings=[("pe.a", M, "pe"), ("pe.b", M, "pe"), ("pe.c", M, "pe")])),
    ("V-CNA-01", dict(kind="pe", statuses={"pe": Status.ERROR})),
    ("V-CNA-02", dict(kind="zip", findings=[("archive.password_unknown", M, "archive")])),
    ("V-CNA-03", dict(kind="zip", data={"archive": {"members": [
        {"name": "a", "stored": None, "skipped": "not extracted: limit"}]}})),
    ("V-CNA-04", dict(kind="zip", children=[child("could not analyze")])),
    ("V-CNA-05", dict(kind="vhd")),
    ("V-NF-01", dict(findings=[("pe.a", M, "pe"), ("pe.b", L, "pe")])),
]


def test_every_rule_has_a_case():
    assert [rid for rid, _ in CASES] == [r.id for r in verdict.RULES]


@pytest.mark.parametrize(("rule_id", "kwargs"), CASES, ids=[c[0] for c in CASES])
def test_rule(rule_id, kwargs):
    r = report(**kwargs)
    rule = next(x for x in verdict.RULES if x.id == rule_id)
    assert r.verdict["rule"] == rule_id, r.verdict["reasons"]
    assert r.verdict["value"] == rule.verdict
    assert r.verdict["reasons"][0]["evidence"]


def test_lnk_with_url_argument():
    ind = [{"type": "url", "sources": ["lnk"], "raw": "http://x.example.com"}]
    r = report(kind="lnk", findings=[("lnk.lolbin_target", H, "lnk")], indicators=ind)
    assert r.verdict["rule"] == "V-MAL-03"


def test_lolbin_alone_is_only_suspicious():
    r = report(kind="lnk", findings=[("lnk.lolbin_target", H, "lnk")])
    assert r.verdict["rule"] == "V-SUS-01"


def test_all_matching_rules_are_listed():
    r = report(kind="ooxml", findings=[("office.dde", H, "office"),
                                       ("office.remote_load", H, "office")])
    assert [x["rule"] for x in r.verdict["reasons"]] == ["V-MAL-04", "V-MAL-05", "V-SUS-01"]


def test_no_findings_confidence():
    assert report().verdict["confidence"] == "medium"
    low = report(statuses={"yara": Status.UNAVAILABLE})
    assert low.verdict["confidence"] == "low"
    assert any("yara" in c for c in low.verdict["caveats"])
    assert report(statuses={"capa": Status.UNAVAILABLE}).verdict["confidence"] == "low"
    assert report(kind="text", statuses={"capa": Status.NOT_APPLICABLE}).verdict["confidence"] \
        == "medium"  # capa only matters for PE
    assert report(kind="empty").verdict["confidence"] == "low"


def test_malicious_keeps_confidence_but_notes_gaps():
    r = report(findings=[("yara.match", H, "yara")], statuses={"strings": Status.TIMEOUT})
    assert (r.verdict["value"], r.verdict["confidence"]) == ("malicious", "high")
    assert any("strings timeout" in c for c in r.verdict["caveats"])


def test_type_failure_beats_no_findings_but_not_evidence():
    assert report(statuses={"pe": Status.TIMEOUT}).verdict["value"] == "could not analyze"
    r = report(findings=[("yara.match", H, "yara")], statuses={"pe": Status.ERROR})
    assert r.verdict["value"] == "malicious"


def test_docs_are_in_sync():
    assert DOCS.read_text(encoding="utf-8") == verdict.render_markdown(), (
        "docs/verdict-rules.md is stale: run `python -m unopened.verdict > docs/verdict-rules.md`"
    )


def test_not_found_never_changes_the_verdict():
    r = report(reputation={"malwarebazaar": "not_found", "virustotal": "not_found"})
    assert (r.verdict["value"], r.verdict["confidence"]) == ("no findings", "medium")


def test_unanswered_reputation_lowers_no_findings():
    r = report(reputation={"malwarebazaar": "error", "virustotal": "skipped"})
    assert r.verdict["confidence"] == "low"
    assert any("no source answered" in c for c in r.verdict["caveats"])


def test_zero_vt_detections_is_not_suspicious():
    assert report(reputation={"virustotal": 0}).verdict["value"] == "no findings"


@pytest.mark.parametrize("keywords, expected", [
    (["CreateObject", "Environ"], "suspicious"),   # M5 corpus 2: autolog.xlsm
    (["CreateObject", "Run"], "malicious"),
    (["URLDownloadToFileA"], "malicious"),
    (["Shell.Application"], "malicious"),
])
def test_auto_run_macro_is_malicious_only_when_it_runs_or_fetches(keywords, expected):
    r = report(kind="ooxml", findings=[("office.autoexec", H, "office"),
                                       ("office.suspicious_keywords", M, "office")],
               data={"office": {"suspicious": [{"keyword": k} for k in keywords]}})
    assert r.verdict["value"] == expected
