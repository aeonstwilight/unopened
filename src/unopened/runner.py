"""Run analyzers so that a crash, hang or missing library becomes a visible status in
the report instead of a silent gap.

Each analyzer runs in a separate worker process with a timeout. The worker runs our
parsing code against the file's bytes; it never runs the sample.
"""

from __future__ import annotations

import importlib.util
import multiprocessing
import sys
import time
import traceback
from typing import Any

from .analyzers import Analyzer, AnalyzerUnavailable, Context
from .model import AnalyzerOutput, AnalyzerResult, Status


def _start_method() -> str:
    # fork is fast and keeps test-time safety guards in the child; macOS and Windows need spawn.
    return "fork" if sys.platform.startswith("linux") else "spawn"


def _missing_module(names: tuple[str, ...]) -> str | None:
    for name in names:
        try:
            if importlib.util.find_spec(name) is None:
                return name
        except (ImportError, ValueError):
            return name
    return None


def _execute(analyzer: Analyzer, ctx: Context) -> tuple[str, Any]:
    try:
        return "ok", analyzer.func(ctx)
    except AnalyzerUnavailable as exc:
        return "unavailable", str(exc)
    except ImportError as exc:
        return "unavailable", f"{type(exc).__name__}: {exc}"
    except Exception as exc:
        tb = traceback.extract_tb(exc.__traceback__)
        where = f" (at {tb[-1].filename.rsplit('/', 1)[-1]}:{tb[-1].lineno})" if tb else ""
        return "error", f"{type(exc).__name__}: {exc}{where}"


def _worker(analyzer: Analyzer, ctx: Context, conn: Any) -> None:
    try:
        conn.send(_execute(analyzer, ctx))
    except Exception as exc:  # e.g. the result could not be pickled
        conn.send(("error", f"could not return result: {type(exc).__name__}: {exc}"))
    finally:
        conn.close()


def _run_isolated(analyzer: Analyzer, ctx: Context, timeout: float) -> tuple[str, Any]:
    mp = multiprocessing.get_context(_start_method())
    recv_conn, send_conn = mp.Pipe(duplex=False)
    proc = mp.Process(target=_worker, args=(analyzer, ctx, send_conn), daemon=True)
    proc.start()
    send_conn.close()
    try:
        if not recv_conn.poll(timeout):
            proc.kill()
            proc.join()
            return "timeout", f"did not finish within {timeout:g} seconds and was stopped"
        try:
            return recv_conn.recv()
        except EOFError:
            proc.join(5)
            return "error", f"worker process died without a result (exit code {proc.exitcode})"
    finally:
        recv_conn.close()
        proc.join(5)
        if proc.is_alive():
            proc.kill()


def run_analyzer(analyzer: Analyzer, ctx: Context, *, isolate: bool = True,
                 time_left: float | None = None) -> AnalyzerResult:
    """`time_left` is what remains of the whole file's time budget (Options.file_timeout);
    the analyzer gets the smaller of that and its own limit, and none at all once it is
    used up."""
    if analyzer.kinds is not None and ctx.file_type.kind not in analyzer.kinds:
        return AnalyzerResult(analyzer.name, Status.NOT_APPLICABLE)
    missing = _missing_module(analyzer.requires)
    if missing:
        hint = f"; install with: {analyzer.install_hint}" if analyzer.install_hint else ""
        return AnalyzerResult(
            analyzer.name, Status.UNAVAILABLE, f"Python package '{missing}' is not installed{hint}"
        )
    budget = ctx.options.file_timeout
    if time_left is not None and time_left <= 0:
        return AnalyzerResult(analyzer.name, Status.TIMEOUT,
                              f"not run: the {budget:g}-second time budget for this file "
                              "was used up by earlier checks")
    own = ctx.options.timeout_for(analyzer.name)
    clipped = time_left is not None and time_left < own
    timeout = time_left if clipped else own
    start = time.monotonic()
    if isolate:
        kind, payload = _run_isolated(analyzer, ctx, timeout)
    else:
        kind, payload = _execute(analyzer, ctx)
    duration = time.monotonic() - start
    if kind == "timeout" and clipped:
        payload = (f"stopped after {timeout:g} seconds, when the {budget:g}-second time "
                   "budget for this file ran out")
    if kind == "timeout" and analyzer.fallback is not None:
        remaining = None if time_left is None else time_left - duration
        return _with_fallback(analyzer, ctx, str(payload), duration, isolate, remaining)
    if kind != "ok":
        return AnalyzerResult(analyzer.name, Status(kind), str(payload), duration)
    out: AnalyzerOutput = payload
    for finding in out.findings:
        finding.source = analyzer.name
    status = Status.PARTIAL if out.errors else Status.OK
    message = "some parts could not be parsed" if out.errors else ""
    return AnalyzerResult(
        analyzer.name, status, message, duration,
        data=out.data, findings=out.findings, errors=out.errors, not_checked=out.not_checked,
    )


def _with_fallback(analyzer: Analyzer, ctx: Context, why: str, spent: float, isolate: bool,
                   time_left: float | None) -> AnalyzerResult:
    """Run the cheaper fallback after a timeout. Success is reported under the original
    analyzer's name as PARTIAL, with the timeout as its error, never as a clean OK."""
    assert analyzer.fallback is not None
    result = run_analyzer(analyzer.fallback, ctx, isolate=isolate, time_left=time_left)
    note = f"full analysis {why}"
    for finding in result.findings:
        finding.source = analyzer.name
    if result.status not in (Status.OK, Status.PARTIAL):
        return AnalyzerResult(
            analyzer.name, Status.TIMEOUT,
            f"{why}; the {analyzer.fallback.name} fallback also failed "
            f"({result.status}: {result.message})", spent + result.duration_seconds,
        )
    return AnalyzerResult(
        analyzer.name, Status.PARTIAL,
        f"{why}; reduced analysis ({analyzer.fallback.title.lower()}) ran instead",
        spent + result.duration_seconds,
        data={**result.data, "fallback": analyzer.fallback.name},
        findings=result.findings, errors=[note, *result.errors],
        not_checked=result.not_checked,
    )
