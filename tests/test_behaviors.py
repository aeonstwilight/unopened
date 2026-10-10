"""Behavior patterns (data/behaviors.toml), tested on synthetic analyzer results.

The capabilities used here are the ones capa reported on the RPISEC lab samples during M5
validation; no sample is involved.
"""

from __future__ import annotations

import pytest

from unopened import behaviors
from unopened.behaviors import PatternError, parse
from unopened.model import AnalyzerResult, Finding, Severity, Status


def results(capa=(), findings=(), signed: bool | None = False, capa_ok=True):
    out = [AnalyzerResult("pe", Status.OK,
                          findings=[Finding(f, Severity.LOW, f) for f in findings])]
    out.append(AnalyzerResult(
        "capa", Status.OK if capa_ok else Status.UNAVAILABLE,
        data={"capabilities": [{"name": c} for c in capa]} if capa_ok else {}))
    if signed is None:
        out.append(AnalyzerResult("authenticode", Status.UNAVAILABLE))
    elif signed == "unverifiable":
        # Signature present, verifier failed (M5: ML-DSA signatures on Microsoft binaries).
        out.append(AnalyzerResult("authenticode", Status.PARTIAL, data={"signed": True},
                                  findings=[Finding("sig.not_verified", Severity.INFO, "x")]))
    else:
        sig = "sig.valid" if signed else "sig.unsigned"
        out.append(AnalyzerResult("authenticode", Status.OK, data={"signed": signed},
                                  findings=[Finding(sig, Severity.INFO, sig)]))
    return out


def matched(rs) -> dict[str, Severity]:
    return {f.id.split(".", 1)[1]: f.severity for f in behaviors.evaluate(rs).findings}


CASES = {
    "reverse_shell": (["create reverse shell"], [], Severity.HIGH),
    "keylogger": (["log keystrokes via polling"], [], Severity.HIGH),
    "file_stealer": (["enumerate files on Windows", "send file via HTTP"], [], Severity.HIGH),
    "shellcode_loader": (["access PEB ldr_data"], ["pe.no_imports"], Severity.HIGH),
    "hidden_strings_and_apis": (["contain obfuscated stackstrings",
                                 "link many functions at runtime"], [], Severity.HIGH),
    "dropper": (["contain an embedded PE file", "extract resource via kernel32 functions",
                 "write file on Windows"], [], Severity.MEDIUM),
    "download_execute": (["download and write a file", "write and execute a file"], [],
                         Severity.MEDIUM),
    "run_key_persistence": (["persist via Run registry key"], [], Severity.MEDIUM),
    "self_delete": (["self delete"], [], Severity.MEDIUM),
}


@pytest.mark.parametrize("pid", CASES)
def test_each_pattern_fires_on_its_evidence(pid):
    capa, findings, severity = CASES[pid]
    assert matched(results(capa, findings)).get(pid) == severity


def test_every_pattern_in_the_data_file_is_tested():
    assert {p.id for p in behaviors.patterns()} == set(CASES)


MULTI = [p for p, (c, f, _) in CASES.items() if len(c) + len(f) > 1]


@pytest.mark.parametrize("pid", MULTI)
def test_partial_evidence_does_not_fire(pid):
    capa, findings, _ = CASES[pid]
    signals = [("capa", c) for c in capa] + [("finding", f) for f in findings]
    for drop in range(len(signals)):
        keep = signals[:drop] + signals[drop + 1:]
        rs = results([v for k, v in keep if k == "capa"], [v for k, v in keep if k == "finding"])
        assert pid not in matched(rs)


@pytest.mark.parametrize("signed", [True, "unverifiable"])
def test_signed_file_keeps_unsigned_only_evidence_at_low(signed):
    capa, _, _ = CASES["dropper"]
    assert matched(results(capa, signed=signed))["dropper"] == Severity.LOW
    # M5: keystroke and reverse-shell capabilities fired on signed TCPView and PuTTY.
    for pid in ("keylogger", "reverse_shell"):
        assert matched(results(CASES[pid][0], signed=signed))[pid] == Severity.LOW
    # Patterns without the guard keep their severity on signed files.
    assert matched(results(["self delete"], signed=True))["self_delete"] == Severity.MEDIUM


def test_unknown_signature_blocks_and_says_so():
    capa, _, _ = CASES["dropper"]
    out = behaviors.evaluate(results(capa, signed=None))
    assert out.findings == []
    assert out.data["blocked_by_signature"] == ["dropper"]
    assert any("signature could not be checked" in n for n in out.not_checked)


def test_capa_not_running_is_noted():
    out = behaviors.evaluate(results(capa_ok=False))
    assert any("capa did not run" in n for n in out.not_checked)


def test_evidence_is_cited():
    (f,) = behaviors.evaluate(results(["create reverse shell"])).findings
    assert f.source == "behavior" and f.title == "Behavior: Reverse shell"
    assert "capa: create reverse shell" in f.detail and "not digitally signed" in f.detail
    (g,) = behaviors.evaluate(results(["create reverse shell"], signed=True)).findings
    assert "the file is signed" in g.detail


def test_substring_match_names_the_capability():
    (f,) = behaviors.evaluate(results(["log keystrokes via application hook"])).findings
    assert "capa: log keystrokes via application hook" in f.detail


@pytest.mark.parametrize("data, message", [
    ({"x": {"title": "t", "severity": "huge", "description": "d", "all": [["capa:a"]]}}, "x"),
    ({"x": {"title": "t", "severity": "high", "description": "d", "all": []}}, "non-empty"),
    ({"x": {"title": "t", "severity": "high", "description": "d", "all": [["cap:a"]]}},
     "bad signal"),
    ({"x": {"severity": "high", "description": "d", "all": [["capa:a"]]}}, "title"),
])
def test_bad_pattern_definitions_are_rejected(data, message):
    with pytest.raises(PatternError, match=message):
        parse(data)


# Through the verdict rules -------------------------------------------------------------

def test_verdicts(make_file, fixtures, monkeypatch):
    from unopened import pipeline
    from unopened.analyzers import Options

    def triage_with(capa: list[str]):
        def fake(rs, pattern_list=None):
            for r in rs:
                if r.name == "capa":
                    r.status, r.data = Status.OK, {"capabilities": [{"name": c} for c in capa]}
                if r.name == "authenticode":
                    r.status = Status.OK
                    r.findings = [Finding("sig.unsigned", Severity.INFO, "unsigned")]
            return real(rs, pattern_list)
        monkeypatch.setattr(pipeline.behaviors, "evaluate", fake)
        return pipeline.triage(make_file("a.exe", fixtures.benign_exe()), Options()).verdict

    real = behaviors.evaluate
    # One HIGH pattern is enough for suspicious.
    assert triage_with(["create reverse shell"])["value"] == "suspicious"
    # A MEDIUM pattern alone is not: droppers wait for the benign-corpus run.
    assert triage_with(list(CASES["dropper"][0]))["value"] == "no findings"
    assert triage_with([])["value"] == "no findings"


# Valid signature tempers a lone YARA match ----------------------------------------------

def _yara_results(valid):
    from unopened.model import AnalyzerResult
    return [
        AnalyzerResult("authenticode", Status.OK, data={"signed": True, "valid": valid}),
        AnalyzerResult("yara", Status.OK, findings=[
            Finding("yara.match", Severity.HIGH, "YARA rule matched: X", "d"),
            Finding("yara.match", Severity.MEDIUM, "YARA rule matched: Y", "d")]),
    ]


def test_valid_signature_caps_yara_at_medium():
    from unopened.pipeline import temper_for_valid_signature
    rs = _yara_results(valid=True)
    temper_for_valid_signature(rs)
    high, medium = rs[1].findings
    assert high.severity == Severity.MEDIUM and "valid Authenticode signature" in high.detail
    assert medium.severity == Severity.MEDIUM and medium.detail == "d"


@pytest.mark.parametrize("valid", [False, None])
def test_invalid_or_unverified_signature_leaves_yara_alone(valid):
    from unopened.pipeline import temper_for_valid_signature
    rs = _yara_results(valid=valid)
    temper_for_valid_signature(rs)
    assert rs[1].findings[0].severity == Severity.HIGH
