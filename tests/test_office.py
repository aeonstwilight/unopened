from __future__ import annotations

import pytest

from unopened import pipeline, runner
from unopened.analyzers import Context, Options, registry
from unopened.identify import identify
from unopened.model import Severity, Status
from unopened.safezip import MemberLimits

pytest.importorskip("oletools")
pytest.importorskip("defusedxml")


def analyze(path, **opts):
    analyzer = next(a for a in registry() if a.name == "office")
    ctx = Context(path, identify(path), Options(**opts), path.stat().st_size)
    return runner.run_analyzer(analyzer, ctx)


def titles(r):
    return {f.title: f.severity for f in r.findings}


@pytest.mark.parametrize("name,build", [("macro.docm", "docm"), ("macro.doc", "legacy_doc")])
def test_macros_autoexec_and_keywords(make_file, office_fx, name, build):
    r = analyze(make_file(name, getattr(office_fx, build)()))
    assert r.status == Status.OK, (r.message, r.errors)
    (module,) = r.data["modules"]
    assert "MsgBox" in module["source"]
    assert [a["keyword"] for a in r.data["autoexec"]] == ["AutoOpen"]
    assert {"Shell", "CreateObject"} <= {s["keyword"] for s in r.data["suspicious"]}
    t = titles(r)
    assert t["Macros run automatically (AutoOpen)"] == Severity.HIGH
    assert t["Contains VBA macros (1 module(s))"] == Severity.MEDIUM
    assert t["Macro code uses suspicious functions"] == Severity.MEDIUM
    line = '    s = "Shell CreateObject WScript.Shell http://payload.example.com/x.exe"'
    assert ["office", line] in r.data["indicator_texts"]


def test_macro_url_reaches_indicator_list(make_file, office_fx):
    report = pipeline.triage(make_file("m.docm", office_fx.docm()), Options())
    url = next(i for i in report.indicators if i["raw"] == "http://payload.example.com/x.exe")
    assert "office" in url["sources"]


def test_plain_docx_has_no_findings(make_file, office_fx):
    r = analyze(make_file("a.docx", office_fx.docx_plain()))
    assert r.status == Status.OK and r.findings == []


def test_remote_template(make_file, office_fx):
    r = analyze(make_file("t.docx", office_fx.docx_remote_template()))
    rel = next(x for x in r.data["external_relationships"] if x["type"] == "attachedTemplate")
    assert rel["target"] == "http://templates.example.com/fixture.dotm"
    assert titles(r)["Document loads a remote template when opened"] == Severity.HIGH
    assert titles(r)["External links (1)"] == Severity.INFO  # the hyperlink


def test_dde_field_split_across_runs(make_file, office_fx):
    r = analyze(make_file("d.docx", office_fx.docx_dde()))
    (dde,) = r.data["dde"]
    assert dde["field"].startswith("DDEAUTO c:")
    assert "cmd.exe" in dde["field"]
    assert titles(r)["DDE field can run a command"] == Severity.HIGH


def test_embedded_package_with_executable_name(make_file, office_fx):
    r = analyze(make_file("p.docx", office_fx.docx_with_embedded_package("invoice.exe")))
    (obj,) = r.data["embedded"]
    assert obj["kind"] == "OLE Package" and obj["filename"] == "invoice.exe"
    assert titles(r)["Embedded file: invoice.exe"] == Severity.HIGH
    assert any("invoice.exe" in n for n in r.not_checked)


def test_embedded_package_in_legacy_doc(make_file, office_fx):
    r = analyze(make_file("p.doc", office_fx.ole_with_package("notes.txt")))
    assert titles(r)["Embedded file: notes.txt"] == Severity.MEDIUM


def test_xlm_macrosheet(make_file, office_fx):
    r = analyze(make_file("x.xlsm", office_fx.xlsm_with_macrosheet()))
    assert r.data["xlm_macros"] is True
    assert titles(r)["Excel 4.0 (XLM) macro sheet present"] == Severity.MEDIUM


def test_zip_bomb_member_is_refused_and_reported(make_file, office_fx):
    path = make_file("bomb.docm", office_fx.ooxml_bomb_vba(64 * 1024 * 1024))
    r = analyze(path, member_limits=MemberLimits(max_size=16 * 1024 * 1024))
    assert r.status == Status.PARTIAL
    assert any("vbaProject.bin" in e and "limit" in e for e in r.errors)
    assert any("safety limit" in n for n in r.not_checked)


def test_ratio_limit(make_file, office_fx):
    path = make_file("bomb.docm", office_fx.ooxml_bomb_vba(8 * 1024 * 1024))
    r = analyze(path)  # default limits: under 50 MB but far above 200:1
    assert any("compression ratio" in e for e in r.errors)


def test_deobfuscation_and_xlm_emulation_stay_off(make_file, office_fx, monkeypatch):
    """olevba must never evaluate VBA expressions or emulate XLM formulas."""
    from oletools import olevba

    calls = []
    real = olevba.VBA_Parser.analyze_macros

    def spy(self, show_decoded_strings=False, deobfuscate=False):
        calls.append(deobfuscate)
        return real(self, show_decoded_strings=show_decoded_strings, deobfuscate=deobfuscate)

    monkeypatch.setattr(olevba.VBA_Parser, "analyze_macros", spy)
    monkeypatch.setattr(olevba, "XLMDEOBFUSCATOR", True)
    path = make_file("m.docm", office_fx.docm())
    analyzer = next(a for a in registry() if a.name == "office")
    r = runner.run_analyzer(analyzer, Context(path, identify(path), Options(), 0), isolate=False)
    assert r.status == Status.OK
    assert calls == [False]
    assert olevba.XLMDEOBFUSCATOR is False


def test_broken_vba_is_reported(make_file, office_fx):
    data = office_fx.ooxml({"word/document.xml": "<x/>", "word/vbaProject.bin": b"not ole"})
    r = analyze(make_file("b.docm", data))
    assert r.status == Status.PARTIAL
    assert any("vbaProject.bin" in e for e in r.errors)
