from __future__ import annotations

import pytest

from unopened import runner
from unopened.analyzers import Context, Options, registry
from unopened.identify import identify
from unopened.model import Severity, Status

pytest.importorskip("pefile")


def analyze(path, name="pe"):
    analyzer = next(a for a in registry() if a.name == name)
    ctx = Context(path, identify(path), Options(), path.stat().st_size)
    return runner.run_analyzer(analyzer, ctx, isolate=False)


def titles(result):
    return [f.title for f in result.findings]


def test_benign_exe(make_file, fixtures):
    r = analyze(make_file("a.exe", fixtures.benign_exe()))
    assert r.status == Status.OK, r.errors
    h = r.data["headers"]
    assert h["format"] == "PE32" and h["machine"] == "x86" and not h["is_dll"]
    assert h["compile_time_utc"].startswith("2023-11-14")
    assert [s["name"] for s in r.data["sections"]] == [".text", ".rdata"]
    assert r.data["entry_point_section"] == ".text"
    assert "ExitProcess" in r.data["imports"]["kernel32.dll"]
    assert len(r.data["imphash"]) == 32
    assert r.data["pdb_path"] == "C:\\build\\fixture\\Release\\fixture.pdb"
    assert "overlay" not in r.data
    assert r.data["signature_directory"]["present"] is False
    # Nothing above INFO for an ordinary small program.
    assert all(f.severity == Severity.INFO for f in r.findings), titles(r)


def test_benign_dll_exports(make_file, fixtures):
    r = analyze(make_file("a.dll", fixtures.benign_dll()))
    assert r.data["headers"]["is_dll"]
    assert r.data["exports"] == ["FixtureInit", "FixtureRun"]


def test_pe32plus(make_file, fixtures):
    r = analyze(make_file("a.exe", fixtures.benign_exe64()))
    assert r.data["headers"]["format"] == "PE32+"
    assert r.data["headers"]["machine"] == "x64"


def test_suspicious_traits(make_file, fixtures):
    r = analyze(make_file("s.exe", fixtures.suspicious_exe()))
    assert r.status == Status.OK, r.errors
    t = titles(r)
    assert "Compile timestamp is in the future" in t
    assert "Packer section name: UPX0" in t
    assert "Writable and executable section: .text" in t
    assert any(x.startswith("High-entropy section: .data") for x in t)
    assert "Executable section with no data in the file: UPX0" in t
    assert any(x.startswith("Data appended after the PE image") for x in t)
    interest = r.data["imports_of_interest"]
    assert interest["process_injection"] == ["CreateRemoteThread", "VirtualAllocEx",
                                             "WriteProcessMemory"]
    assert interest["input_capture"] == ["GetAsyncKeyState", "SetWindowsHookExW"]
    assert "IsDebuggerPresent" in interest["anti_analysis"]
    assert r.data["overlay"]["size"] == 4096


@pytest.mark.parametrize(("timestamp", "title"), [
    (0, "Compile timestamp is zeroed"),
    (0x2A425E19, "Borland/Delphi default timestamp (1992-06-19)"),
    (500_000_000, "Implausibly old compile timestamp"),
])
def test_timestamp_rules(make_file, fixtures, timestamp, title):
    r = analyze(make_file("t.exe", fixtures.build_pe(fixtures.PESpec(timestamp=timestamp))))
    assert title in titles(r)


def test_entry_point_outside_sections(make_file, fixtures):
    r = analyze(make_file("e.exe", fixtures.build_pe(fixtures.PESpec(entry_point=0x90000))))
    assert "Entry point is outside every section" in titles(r)


def test_entry_point_in_non_executable_section(make_file, fixtures):
    r = analyze(make_file("e.exe", fixtures.build_pe(fixtures.PESpec(entry_point=0x2000))))
    assert "Entry point is in a non-executable section (.rdata)" in titles(r)


def test_no_imports(make_file, fixtures):
    r = analyze(make_file("n.exe", fixtures.build_pe(fixtures.PESpec(imports={}))))
    assert "No imports" in titles(r)
    assert r.data["imphash"] is None


def test_signature_directory_and_overlay_separated(make_file, fixtures):
    r = analyze(make_file("f.exe", fixtures.fake_signed_exe()))
    assert r.data["signature_directory"]["present"] is True
    assert "overlay" not in r.data  # the certificate table is not an overlay


def test_truncated_pe_is_reported_not_hidden(make_file, fixtures):
    data = fixtures.benign_exe()
    r = analyze(make_file("cut.exe", data[:0x160]))  # cut inside the headers
    assert r.status in (Status.ERROR, Status.PARTIAL) or any(
        t.startswith("File is truncated") for t in titles(r)
    ), (r.status, r.message, titles(r))


def test_truncated_section_data(make_file, fixtures):
    data = fixtures.benign_exe()
    r = analyze(make_file("cut.exe", data[: len(data) - 0x100]))
    assert "File is truncated: section .rdata extends past the end" in titles(r)
    assert any("missing from the file" in n for n in r.not_checked)


def test_truncated_after_headers_is_partial_or_flagged(make_file, fixtures):
    data = fixtures.strings_exe()
    r = analyze(make_file("cut.exe", data[:0x500]))  # .rdata (imports) cut off
    assert r.status in (Status.ERROR, Status.PARTIAL) or any(
        "anomalies" in t for t in titles(r)
    ), (r.status, titles(r))


def test_mz_only_fails_loudly(make_file):
    r = analyze(make_file("dos.exe", b"MZ" + bytes(0x3A) + b"\x80\0\0\0" + bytes(200)))
    assert r.status == Status.ERROR
    assert "not a parseable PE" in r.message


def test_not_applicable_to_other_types(make_file):
    r = analyze(make_file("a.txt", b"hello world, this is text\n"))
    assert r.status == Status.NOT_APPLICABLE
