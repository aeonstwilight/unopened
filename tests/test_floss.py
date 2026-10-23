"""FLOSS (M6): decoded and stack strings, kept out of the verdict for now."""

from __future__ import annotations

import json

import pytest

from unopened import pipeline, runner
from unopened.analyzers import Context, Options, floss_analyzer, registry
from unopened.identify import identify
from unopened.model import Status

pytest.importorskip("floss")


def run(path):
    analyzer = next(a for a in registry() if a.name == "floss")
    return runner.run_analyzer(analyzer, Context(path, identify(path), Options(),
                                                 path.stat().st_size))


def test_stack_string_is_recovered(make_file, fixtures):
    r = run(make_file("s.exe", fixtures.stackstring_exe()))
    assert r.status == Status.OK, r.message
    assert [s["string"] for s in r.data["stack"]] == [fixtures.STACK_STRING]
    assert r.findings[0].id == "floss.recovered"


def test_plain_program_has_nothing_to_recover(make_file, fixtures):
    r = run(make_file("a.exe", fixtures.benign_exe()))
    assert r.status == Status.OK
    assert r.findings == [] and not any(r.data[k] for k in floss_analyzer.KINDS)


def test_recovered_url_becomes_an_indicator_but_not_a_finding(make_file, fixtures):
    report = pipeline.triage(make_file("s.exe", fixtures.stackstring_exe()), Options())
    url = next(i for i in report.indicators if i["raw"] == fixtures.STACK_STRING)
    assert url["sources"] == ["floss"]
    # FLOSS-only indicators must not produce findings the verdict could use.
    assert "indicators.network" not in {f.id for f in report.findings()}


def test_floss_does_not_change_the_verdict(make_file, fixtures, monkeypatch):
    path = make_file("s.exe", fixtures.stackstring_exe())
    with_floss = pipeline.triage(path, Options()).verdict
    monkeypatch.setattr(runner, "_missing_module",
                        lambda names: "floss" if "floss" in names else None)
    without = pipeline.triage(path, Options()).verdict
    assert with_floss["value"] == without["value"]
    assert with_floss["rule"] == without["rule"]


def test_dotnet_is_skipped_and_said(make_file, fixtures, monkeypatch):
    monkeypatch.setattr(floss_analyzer, "_is_dotnet", lambda path: True)
    r = run(make_file("a.exe", fixtures.benign_exe()))
    assert r.data["skipped"] == ".NET"
    assert any(".NET" in n for n in r.not_checked)


def test_large_file_is_skipped_and_said(make_file, fixtures, monkeypatch):
    monkeypatch.setattr(floss_analyzer, "MAX_SAMPLE_SIZE", 100)
    r = run(make_file("a.exe", fixtures.benign_exe()))
    assert r.data["skipped"] == "file too large"
    assert any("over" in n for n in r.not_checked)


def test_missing_floss_is_unavailable_with_hint(make_file, fixtures, monkeypatch):
    monkeypatch.setattr(runner, "_missing_module",
                        lambda names: "floss" if "floss" in names else None)
    r = run(make_file("a.exe", fixtures.benign_exe()))
    assert r.status == Status.UNAVAILABLE and "unopened[floss]" in r.message


def test_reports_show_floss_strings_defanged(make_file, fixtures):
    from unopened.report import json_report, markdown

    report = pipeline.triage(make_file("s.exe", fixtures.stackstring_exe()), Options())
    md = markdown.render(report)
    assert "## Decoded and stack strings (FLOSS)" in md
    assert "hxxp://floss.example[.]com/stage2" in md
    assert fixtures.STACK_STRING not in md
    doc = json.loads(json_report.render(report))
    assert doc["analyzers"]["floss"]["data"]["stack"][0]["string"] == \
        "hxxp://floss.example[.]com/stage2"


def test_not_applicable_to_other_types(make_file):
    assert run(make_file("a.txt", b"plain text words here\n")).status == Status.NOT_APPLICABLE
