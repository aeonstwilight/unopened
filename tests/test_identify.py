from __future__ import annotations

import pytest

from unopened.identify import check_name, identify
from unopened.model import FileType, Severity


@pytest.mark.parametrize(
    ("name", "builder", "kind", "subtype"),
    [
        ("a.exe", lambda b: b.benign_exe(), "pe", "exe"),
        ("a.dll", lambda b: b.benign_dll(), "pe", "dll"),
        ("a.exe", lambda b: b.benign_exe64(), "pe", "exe"),
        ("a.lnk", lambda b: b.lnk_header(), "lnk", ""),
        ("a.iso", lambda b: b.iso_header(), "iso", ""),
        ("a.docx", lambda b: b.ooxml_zip(), "ooxml", "word"),
        ("a.zip", lambda b: b.plain_zip(), "zip", ""),
    ],
)
def test_identifies_by_content(make_file, fixtures, name, builder, kind, subtype):
    ft = identify(make_file(name, builder(fixtures)))
    assert (ft.kind, ft.subtype) == (kind, subtype)
    assert ft.mismatches == []


@pytest.mark.parametrize(
    ("data", "kind"),
    [
        (bytes.fromhex("D0CF11E0A1B11AE1") + bytes(504), "ole"),
        (b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n", "pdf"),
        (b"junk" * 10 + b"%PDF-1.4\n", "pdf"),  # header not at offset 0 still counts
        (b"7z\xbc\xaf\x27\x1c\x00\x04" + bytes(24), "7z"),
        (b"", "empty"),
        (b"\x00\x01\x02\x03\xff\xfe\xfd" * 20, "unknown"),
        (b"just some notes\nnothing to see here\n", "text"),
    ],
)
def test_other_types(make_file, data, kind):
    assert identify(make_file("sample.bin", data)).kind == kind


def test_pe64_details(make_file, fixtures):
    ft = identify(make_file("a.exe", fixtures.benign_exe64()))
    assert ft.details["format"] == "PE32+"
    assert ft.details["machine"] == "x64"


def test_ooxml_with_macros(make_file, fixtures):
    ft = identify(make_file("a.docm", fixtures.ooxml_zip(macros=True)))
    assert ft.details["vba_project"] is True
    assert "macros" in ft.description


@pytest.mark.parametrize(
    ("text", "lang"),
    [
        ("$url = 'x'\nInvoke-WebRequest -Uri $url\nWrite-Host done\n", "powershell"),
        ("var s = new ActiveXObject('WScript.Shell');\nfunction f() { return 1; }\n", "javascript"),
        ("Dim x\nSet o = CreateObject(\"Scripting.FileSystemObject\")\nEnd Sub\n", "vbscript"),
        ("@echo off\r\nset /a n=1\r\ngoto :done\r\n:done\r\n", "batch"),
    ],
)
def test_script_heuristics(make_file, text, lang):
    ft = identify(make_file("s.txt", text.encode()))
    assert (ft.kind, ft.subtype) == ("script", lang)


def test_utf16_text_is_text_not_binary(make_file):
    data = "﻿@echo off\r\nset /a n=1\r\ngoto :x\r\n".encode("utf-16-le")
    ft = identify(make_file("s.bat", b"\xff\xfe" + data[2:]))
    assert ft.kind == "script"


def test_mz_without_pe_header(make_file):
    ft = identify(make_file("old.exe", b"MZ" + bytes(0x3A) + b"\x80\0\0\0" + bytes(200)))
    assert ft.kind == "mz"


def test_one_byte_and_truncated_mz(make_file):
    assert identify(make_file("x", b"M")).kind in ("text", "unknown")
    assert identify(make_file("x.exe", b"MZ\x90\x00")).kind == "mz"


def test_pe_renamed_docx_is_high(make_file, fixtures):
    ft = identify(make_file("report.docx", fixtures.benign_exe()))
    assert ft.kind == "pe"
    assert [m.severity for m in ft.mismatches] == [Severity.HIGH]
    assert ".docx" in ft.mismatches[0].message


def test_double_extension(make_file, fixtures):
    ft = identify(make_file("invoice.pdf.exe", fixtures.benign_exe()))
    assert any("Double extension" in m.message for m in ft.mismatches)
    assert all(m.severity == Severity.HIGH for m in ft.mismatches)


def test_rtlo_in_name():
    ft = FileType("pe", "PE32 executable", subtype="exe")
    mismatches = check_name("invoice‮fdp.exe", ft)
    assert mismatches[0].severity == Severity.HIGH
    assert "direction-override" in mismatches[0].message


def test_padding_spaces():
    ft = FileType("pe", "PE32 executable", subtype="exe")
    assert any("spaces" in m.message for m in check_name("photo.jpg          .exe", ft))


def test_script_with_wrong_extension_is_medium(make_file):
    ft = identify(make_file("notes.txt", b"@echo off\r\nset /a n=1\r\ngoto :x\r\n"))
    assert [m.severity for m in ft.mismatches] == [Severity.MEDIUM]


def test_no_extension_is_info(make_file, fixtures):
    ft = identify(make_file("payload", fixtures.benign_exe()))
    assert [m.severity for m in ft.mismatches] == [Severity.INFO]


def test_unknown_and_text_never_claim_mismatch(make_file):
    assert identify(make_file("a.pdf", b"\x00\x01\x02\xff" * 50)).mismatches == []
    assert identify(make_file("a.exe", b"hello there, plain words\n")).mismatches == []


@pytest.mark.parametrize(("name", "build", "subtype"), [
    ("a.doc", "legacy_doc", "word"),
    ("a.xls", "legacy_xls", "excel"),
    ("a.msi", "msi_like", "msi"),
])
def test_ole_subtypes(make_file, office_fx, name, build, subtype):
    pytest.importorskip("olefile")
    ft = identify(make_file(name, getattr(office_fx, build)()))
    assert (ft.kind, ft.subtype) == ("ole", subtype)
    assert ft.mismatches == []


def test_doc_renamed_xls_is_flagged(make_file, office_fx):
    pytest.importorskip("olefile")
    ft = identify(make_file("budget.xls", office_fx.legacy_doc()))
    assert ft.details["vba_project"] is True
    assert any(".xls does not match" in m.message for m in ft.mismatches)


@pytest.mark.parametrize("name", ["sample.malware", "a.bin", "b.vir", "c.dat"])
def test_pe_with_storage_extension_is_low_not_high(make_file, fixtures, name):
    # Found in M5 validation: lab samples named *.malware were called suspicious on the
    # name alone. A storage extension is not a disguise; a document extension is.
    ft = identify(make_file(name, fixtures.benign_exe()))
    assert [m.severity for m in ft.mismatches] == [Severity.LOW]
    assert "not a disguise" in ft.mismatches[0].message


@pytest.mark.parametrize("name", ["scan.pdf", "photo.jpg", "data.zip", "notes.txt"])
def test_pe_with_decoy_extension_stays_high(make_file, fixtures, name):
    ft = identify(make_file(name, fixtures.benign_exe()))
    assert [m.severity for m in ft.mismatches] == [Severity.HIGH]


@pytest.mark.parametrize(("name", "lang"), [
    ("a.js", "javascript"), ("a.ps1", "powershell"), ("a.bat", "batch"), ("a.vbs", "vbscript"),
])
def test_padded_script_is_identified_by_name(make_file, name, lang):
    # M5 holdout: scripts led by junk padding scored nothing on the content heuristics, were
    # called plain text, and the script analyzer never ran.
    padding = "".join(f"qzx{i} wvk{i * 7} " for i in range(4000)) + "\n"
    ft = identify(make_file(name, padding.encode()))
    assert (ft.kind, ft.subtype) == ("script", lang)
    assert ft.details["identified_by"] == "extension"
    assert ft.mismatches == []


def test_text_with_other_names_stays_text(make_file):
    for name in ("notes.txt", "README", "a.exe"):
        assert identify(make_file(name, b"plain words only\n")).kind == "text"
