"""RTF objects, Equation Editor exploit shape, remote content; VHD identification (M11)."""

from __future__ import annotations

import pytest

from unopened import pipeline
from unopened.analyzers import Options
from unopened.identify import identify

pytest.importorskip("oletools")


def triage(make_file, name, data):
    return pipeline.triage(make_file(name, data), Options(hunt=False))


def ids(report):
    return {f.id: f.severity.value for f in report.findings()}


def test_rtf_identified_from_content_even_named_doc(web_fx, make_file):
    ft = identify(make_file("letter.doc", web_fx.rtf_plain()))
    assert ft.kind == "rtf" and not ft.mismatches
    assert identify(make_file("x.rtf", web_fx.rtf_obfuscated_header())).kind == "rtf"


def test_plain_rtf_is_quiet(web_fx, make_file):
    r = triage(make_file, "a.rtf", web_fx.rtf_plain())
    assert r.verdict["value"] == "no findings"
    assert not [f for f in r.findings() if f.id.startswith("rtf.")]
    assert r.result("rtf").status.value == "ok"


def test_packaged_executable_is_extracted_and_malicious(web_fx, make_file):
    r = triage(make_file, "a.rtf", web_fx.rtf_package("invoice.exe"))
    assert ids(r)["rtf.embedded_executable"] == "high"
    assert r.verdict["rule"] == "V-MAL-06"
    (child,) = r.children
    assert child["member"]["name"] == "invoice.exe"


def test_packaged_document_is_medium(web_fx, make_file):
    r = triage(make_file, "a.rtf", web_fx.rtf_package("notes.txt"))
    assert ids(r)["rtf.embedded_file"] == "medium"


def test_equation_object_alone_is_medium(web_fx, make_file):
    r = triage(make_file, "a.rtf", web_fx.rtf_equation())
    assert ids(r) == {"rtf.equation_object": "medium"}
    (obj,) = r.result("rtf").data["objects"]
    assert obj["equation"]["font_name_length"] == len("Times New Roman")
    assert r.verdict["value"] == "no findings"


def test_equation_font_overflow_is_malicious(web_fx, make_file):
    r = triage(make_file, "a.rtf", web_fx.rtf_equation_overflow())
    assert ids(r)["rtf.equation_exploit"] == "high"
    assert r.verdict["value"] == "malicious" and r.verdict["rule"] == "V-MAL-12"


def test_auto_updating_equation_is_malicious(web_fx, make_file):
    r = triage(make_file, "a.rtf", web_fx.rtf_equation(objupdate=True))
    assert {"rtf.equation_object", "rtf.objupdate"} <= set(ids(r))
    assert r.verdict["rule"] == "V-MAL-12"


def test_remote_template(web_fx, make_file):
    r = triage(make_file, "a.rtf", web_fx.rtf_remote_template())
    assert ids(r)["rtf.remote_template"] == "high"
    assert r.verdict["rule"] == "V-MAL-05"
    assert any("templates.example.net" in i.get("raw", "") for i in r.indicators)


def test_non_standard_header(web_fx, make_file):
    r = triage(make_file, "a.rtf", web_fx.rtf_obfuscated_header())
    assert ids(r)["rtf.malformed_header"] == "medium"


@pytest.mark.parametrize("builder,name,fmt", [("vhd_fixed", "disk.vhd", "VHD"),
                                               ("vhdx", "disk.vhdx", "VHDX")])
def test_virtual_disk_is_could_not_analyze(web_fx, make_file, builder, name, fmt):
    r = triage(make_file, name, getattr(web_fx, builder)())
    assert r.file_type.kind == "vhd"
    assert r.verdict["value"] == "could not analyze" and r.verdict["rule"] == "V-CNA-05"
    assert r.result("vhd").data["format"] == fmt
    assert any("inside the virtual disk" in n.reason for n in r.not_checked)


def test_fixed_vhd_footer_fields(web_fx, make_file):
    r = triage(make_file, "d.vhd", web_fx.vhd_fixed())
    d = r.result("vhd").data
    assert d["disk_type"] == "fixed" and d["creator"] == "fixt"


def test_disk_image_named_as_document(web_fx, make_file):
    ft = identify(make_file("scan.pdf", web_fx.vhd_fixed()))
    assert "identify.extension_mismatch" in {m.id for m in ft.mismatches}
