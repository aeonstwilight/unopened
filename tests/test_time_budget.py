"""The whole-file time budget (Options.file_timeout), added in M5 validation.

Analyzer limits alone add up: analyzers run one after another, and every archive member
gets a fresh set, so one benign file took 1,356 s although no analyzer may run past 300 s.
These tests use a stand-in analyzer that only sleeps; no sample is involved.
"""

from __future__ import annotations

import time

from unopened import pipeline
from unopened.analyzers import Analyzer, Options, registry
from unopened.model import AnalyzerOutput, Status

SLEEP = 0.6


def _sleep(ctx):
    time.sleep(SLEEP)
    return AnalyzerOutput()


def _with_sleepers(monkeypatch, n: int, kinds=None):
    real = [a for a in registry() if a.name in ("hashes", "archive")]
    slow = [Analyzer(f"slow{i}", f"Slow check {i}", _sleep,
                     kinds=frozenset(kinds) if kinds else None) for i in range(n)]
    monkeypatch.setattr(pipeline, "registry", lambda: real + slow)


def test_budget_stops_analyzers_that_would_run_past_it(make_file, monkeypatch):
    _with_sleepers(monkeypatch, 5)
    path = make_file("a.txt", b"plain text, nothing to see")
    start = time.monotonic()
    report = pipeline.triage(path, Options(file_timeout=1.0, hunt=False))
    elapsed = time.monotonic() - start
    # Five 0.6 s checks would take 3 s; the budget holds it near 1 s.
    assert elapsed < 2.0
    status = {r.name: r for r in report.results}
    timed_out = [n for n in status if n.startswith("slow") and status[n].status == Status.TIMEOUT]
    assert timed_out, "later checks must be reported, not silently dropped"
    assert any("time budget" in status[n].message for n in timed_out)
    # Fail loudly: each one is listed under Not checked, and confidence drops.
    not_checked = " ".join(f"{n.check} {n.reason}" for n in report.not_checked)
    assert all(f"Slow check {n[4:]}" in not_checked for n in timed_out)
    assert report.verdict["confidence"] == "low"


def test_members_left_when_the_budget_runs_out_are_named(make_file, arch_fx, monkeypatch):
    _with_sleepers(monkeypatch, 1, kinds={"unknown", "text", "script"})
    members = {f"m{i}.txt": f"member {i}".encode() for i in range(6)}
    path = make_file("bundle.zip", arch_fx.zip_plain(members))
    report = pipeline.triage(path, Options(file_timeout=1.5, hunt=False))
    archive = next(r for r in report.results if r.name == "archive")
    skipped = archive.data.get("members_not_analyzed", [])
    assert skipped and len(report.children) + len(skipped) == 6
    assert any("not analyzed" in n.reason and "time budget" in n.reason
               for n in report.not_checked)
    assert report.verdict["value"] == "no findings"
    assert report.verdict["confidence"] == "low"
    assert any("member(s) not analyzed" in c for c in report.verdict["caveats"])


def test_default_budget_leaves_ordinary_files_alone(make_file, fixtures):
    report = pipeline.triage(make_file("a.exe", fixtures.benign_exe()), Options(hunt=False))
    assert not any("time budget" in r.message for r in report.results)
    assert Options().file_timeout == 900.0
