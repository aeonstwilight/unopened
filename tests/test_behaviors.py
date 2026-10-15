"""Behavior patterns (data/behaviors.toml), tested on synthetic analyzer results.

The capabilities used here are the ones capa reported on the RPISEC lab samples during M5
validation; no sample is involved.
"""

from __future__ import annotations

import pytest

from unopened import behaviors
from unopened.behaviors import PatternError, parse
from unopened.model import AnalyzerResult, Finding, Severity, Status


def _finding(spec: str) -> Finding:
    # "id" is LOW; "id@medium" gives the severity.
    fid, _, level = spec.partition("@")
    return Finding(fid, Severity(level or "low"), fid)


def results(capa=(), findings=(), signed: bool | None = False, capa_ok=True):
    out = [AnalyzerResult("pe", Status.OK, findings=[_finding(f) for f in findings])]
    out.append(AnalyzerResult(
        "capa", Status.OK if capa_ok else Status.UNAVAILABLE,
        data={"capabilities": [{"name": c} for c in capa]} if capa_ok else {}))
    if signed is None:
        out.append(AnalyzerResult("authenticode", Status.UNAVAILABLE))
    elif signed == "failed":
        # Signature present but does not verify (M5 holdout: untrusted certificates).
        out.append(AnalyzerResult("authenticode", Status.OK,
                                  data={"signed": True, "valid": False},
                                  findings=[Finding("sig.certificate_error", Severity.MEDIUM,
                                                    "x")]))
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
    "obfuscated_persistent_script": ([], ["script.obfuscated", "script.ps.persistence"],
                                     Severity.HIGH),
    "untrusted_signer_injection": ([], ["sig.certificate_error",
                                        "pe.imports.process_injection"], Severity.HIGH),
    "flagged_dropper": (["contain an embedded PE file"], ["yara.match"], Severity.HIGH),
    "hidden_programs_in_image": ([], ["archive.hidden_files", "container.runnable_member"],
                                 Severity.HIGH),
    "uac_bypass": (["bypass UAC via ICMLuaUtil"], [], Severity.HIGH),
    "dotnet_crypter": (["load .NET assembly"], ["pe.dotnet", "pe.high_entropy_section@medium"],
                       Severity.HIGH),
    "api_hashing": (["resolve function by Brute Ratel Badger hash"], [], Severity.HIGH),
    "com_script_with_payload_line": ([], ["script.js.activex", "script.long_line@medium"],
                                     Severity.HIGH),
    "obfuscated_self_reading_batch": ([], ["script.obfuscated", "script.bat.self_read"],
                                      Severity.HIGH),
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


def test_failed_signature_lends_no_trust():
    # M5 holdout: Vidar samples signed with untrusted certificates; a side-loaded DLL
    # signed by an untrusted publisher used a UAC bypass.
    for pid in ("dropper", "keylogger", "reverse_shell", "uac_bypass"):
        out = matched(results(CASES[pid][0], signed="failed"))
        assert out[pid] == CASES[pid][2]
    (f,) = [f for f in behaviors.evaluate(results(["create reverse shell"], signed="failed"))
            .findings]
    assert "its signature does not verify" in f.detail


# Evidence seen on M5 holdout samples, as synthetic analyzer results ------------------

def test_holdout_tiny_loader():
    # 4.6 KB PE with one import, PEB walking and stack strings; run 1 said no findings.
    capa = ["access PEB ldr_data", "contain obfuscated stackstrings", "encode data using XOR",
            "encrypt data using RC4 PRGA", "resolve function by parsing PE exports"]
    out = matched(results(capa, ["pe.small_import_table"]))
    assert out["shellcode_loader"] == Severity.HIGH
    assert out["hidden_strings_and_apis"] == Severity.HIGH


def test_holdout_untrusted_signer_with_injection_imports():
    out = matched(results([], ["pe.imports.process_injection", "pe.timestamp_zeroed"],
                          signed="failed"))
    assert out["untrusted_signer_injection"] == Severity.HIGH
    # A valid signature does not satisfy the pattern.
    assert "untrusted_signer_injection" not in matched(
        results([], ["pe.imports.process_injection"], signed=True))


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


# Valid signature lowers packing (M5 corpus 2: Rufus, UPX-packed and signed) ------------

@pytest.mark.parametrize("valid, expected", [(True, Severity.LOW), (False, Severity.MEDIUM)])
def test_packing_on_a_validly_signed_file_is_low(valid, expected):
    from unopened.model import AnalyzerResult
    from unopened.pipeline import temper_for_valid_signature
    rs = [AnalyzerResult("authenticode", Status.OK, data={"signed": True, "valid": valid}),
          AnalyzerResult("pe", Status.OK, findings=[
              Finding("pe.packer_section", Severity.MEDIUM, "Packer section name: UPX0", "d"),
              Finding("pe.high_entropy_section", Severity.MEDIUM, "High entropy", "d"),
              Finding("pe.no_imports", Severity.MEDIUM, "No imports", "d")])]
    temper_for_valid_signature(rs)
    packer, entropy, other = rs[1].findings
    assert packer.severity == entropy.severity == expected
    assert other.severity == Severity.MEDIUM  # only packing findings are tempered
    if valid:
        assert "valid Authenticode signature" in packer.detail


# Holdout set 2 ---------------------------------------------------------------------

def test_severity_qualified_signal_needs_that_severity():
    # A high-entropy .rsrc is LOW (resources are often compressed images); only a MEDIUM
    # one, the code section, counts toward the crypter pattern.
    capa = ["load .NET assembly", "invoke .NET assembly method"]
    assert "dotnet_crypter" not in matched(
        results(capa, ["pe.dotnet", "pe.high_entropy_section"]))
    assert "com_script_with_payload_line" not in matched(
        results([], ["script.js.activex", "script.long_line"]))


def test_holdout2_dotnet_crypter():
    # Unsigned .NET RAT: .text at 7.74 of 8.0 (MEDIUM), .rsrc at 7.54 (LOW), and capa's
    # assembly loading. Run 1: no findings.
    capa = ["access .NET resource", "compile .NET assembly", "compiled to the .NET platform",
            "invoke .NET assembly method", "load .NET assembly", "manipulate console buffer"]
    out = matched(results(capa, ["pe.dotnet", "pe.high_entropy_section@medium",
                                 "pe.timestamp_future@medium"]))
    assert out["dotnet_crypter"] == Severity.HIGH
    # Signed: the same evidence is only a lead.
    assert matched(results(capa, ["pe.dotnet", "pe.high_entropy_section@medium"],
                           signed=True))["dotnet_crypter"] == Severity.LOW


def test_holdout2_api_hashing_and_other_resolution():
    assert matched(results(["resolve function by FNV-1a hash"]))["api_hashing"] == Severity.HIGH
    # Walking the export table by name is not hashing.
    assert "api_hashing" not in matched(results(["resolve function by parsing PE exports"]))
    # Hashing data is not resolving functions.
    assert "api_hashing" not in matched(results(["hash data using murmur3"]))


def test_bad_regex_and_severity_are_rejected():
    with pytest.raises(PatternError):
        parse({"x": {"title": "t", "severity": "high", "description": "d",
                     "all": [["capa/("]]}})
    with pytest.raises(PatternError):
        parse({"x": {"title": "t", "severity": "high", "description": "d",
                     "all": [["finding:pe.dotnet@severe"]]}})
