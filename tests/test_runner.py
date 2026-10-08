from __future__ import annotations

import os
import time

from unopened import pipeline, runner
from unopened.analyzers import Analyzer, AnalyzerUnavailable, Context, Options
from unopened.model import AnalyzerOutput, FileType, Finding, Severity, Status


def ctx(tmp_path, timeout=5.0):
    p = tmp_path / "f.bin"
    p.write_bytes(b"data")
    return Context(p, FileType("unknown", "x"), Options(timeout=timeout), 4)


def crash(c):
    raise RuntimeError("boom")


def hang(c):
    time.sleep(30)


def die(c):
    os._exit(7)


def unavailable(c):
    raise AnalyzerUnavailable("library present but broken")


def ok(c):
    return AnalyzerOutput(data={"x": 1}, findings=[Finding("test.ok", Severity.LOW, "t")])


def partial(c):
    return AnalyzerOutput(data={"x": 1}, errors=["section table: bad"])


def test_ok_in_worker(tmp_path):
    r = runner.run_analyzer(Analyzer("ok", "OK check", ok), ctx(tmp_path))
    assert r.status == Status.OK and r.data == {"x": 1}
    assert r.findings[0].source == "ok"


def test_exception_becomes_error(tmp_path):
    r = runner.run_analyzer(Analyzer("c", "Crashy", crash), ctx(tmp_path))
    assert r.status == Status.ERROR
    assert "RuntimeError: boom" in r.message


def test_hang_becomes_timeout(tmp_path):
    start = time.monotonic()
    r = runner.run_analyzer(Analyzer("h", "Hangs", hang), ctx(tmp_path, timeout=0.5))
    assert r.status == Status.TIMEOUT
    assert time.monotonic() - start < 10


def test_worker_death_becomes_error(tmp_path):
    r = runner.run_analyzer(Analyzer("d", "Dies", die), ctx(tmp_path))
    assert r.status == Status.ERROR
    assert "exit code 7" in r.message


def test_missing_library_is_unavailable(tmp_path):
    a = Analyzer("m", "Missing", ok, requires=("no_such_module_xyz",), install_hint="pip install x")
    r = runner.run_analyzer(a, ctx(tmp_path))
    assert r.status == Status.UNAVAILABLE
    assert "no_such_module_xyz" in r.message and "pip install x" in r.message


def test_analyzer_unavailable_exception(tmp_path):
    r = runner.run_analyzer(Analyzer("u", "U", unavailable), ctx(tmp_path))
    assert r.status == Status.UNAVAILABLE


def test_partial(tmp_path):
    r = runner.run_analyzer(Analyzer("p", "P", partial), ctx(tmp_path))
    assert r.status == Status.PARTIAL
    assert r.errors == ["section table: bad"]


def test_not_applicable(tmp_path):
    a = Analyzer("pe", "PE", ok, kinds=frozenset({"pe"}))
    assert runner.run_analyzer(a, ctx(tmp_path)).status == Status.NOT_APPLICABLE


def test_every_incomplete_status_lands_in_not_checked(tmp_path, monkeypatch):
    fakes = [
        Analyzer("c", "Crashy check", crash),
        Analyzer("h", "Hanging check", hang),
        Analyzer("m", "Missing-library check", ok, requires=("no_such_module_xyz",)),
        Analyzer("p", "Partial check", partial),
    ]
    monkeypatch.setattr(pipeline, "registry", lambda: fakes)
    path = tmp_path / "f.bin"
    path.write_bytes(b"data")
    report = pipeline.triage(path, Options(timeout=0.5))
    checks = " | ".join(f"{n.check}: {n.reason}" for n in report.not_checked)
    assert "Crashy check: error" in checks
    assert "Hanging check: timeout" in checks
    assert "Missing-library check: unavailable" in checks
    assert "Partial check: part: failed to parse: section table: bad" in checks
