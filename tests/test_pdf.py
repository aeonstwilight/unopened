from __future__ import annotations

import pytest

from unopened import pipeline, runner
from unopened.analyzers import Context, Options, registry
from unopened.analyzers.pdf import keyword_scan
from unopened.extraction import Limits
from unopened.identify import identify
from unopened.model import Severity, Status

pytest.importorskip("pypdf")


def analyze(path, tmp_path, limits=None):
    limits = limits or Limits()
    analyzer = next(a for a in registry() if a.name == "pdf")
    out = tmp_path / "x"
    out.mkdir(exist_ok=True)
    ctx = Context(path, identify(path), Options(limits=limits), path.stat().st_size,
                  extract_dir=out, files_left=limits.max_files, bytes_left=limits.max_total_size)
    return runner.run_analyzer(analyzer, ctx)


def ids(r):
    return {f.id: f.severity for f in r.findings}


def test_plain_pdf_is_quiet(make_file, arch_fx, tmp_path):
    r = analyze(make_file("p.pdf", arch_fx.pdf_plain()), tmp_path)
    assert r.status == Status.OK and r.findings == []


def test_openaction_javascript(make_file, arch_fx, tmp_path):
    r = analyze(make_file("j.pdf", arch_fx.pdf_openaction_js()), tmp_path)
    (js,) = r.data["javascript"]
    assert js["auto"] and "app.alert" in js["source"]
    assert "http://pdf.example.com/p.exe" in js["deobfuscated"]
    assert ids(r)["pdf.auto_javascript"] == Severity.HIGH
    assert ids(r)["pdf.javascript"] == Severity.MEDIUM


def test_obfuscated_names(make_file, arch_fx, tmp_path):
    data = arch_fx.pdf_openaction_js(obfuscate_names=True)
    counts, obfuscated = keyword_scan(data)
    assert counts["/JavaScript"] == 1 and obfuscated == {"/JavaScript": 1}
    r = analyze(make_file("o.pdf", data), tmp_path)
    assert "pdf.obfuscated_names" in ids(r)
    assert r.data["javascript"], "the parser still found the script behind the escaped name"


def test_launch(make_file, arch_fx, tmp_path):
    r = analyze(make_file("l.pdf", arch_fx.pdf_launch()), tmp_path)
    (launch,) = r.data["launch"]
    assert launch["windows_file"] == "cmd.exe" and launch["auto"]
    assert ids(r)["pdf.launch"] == Severity.HIGH


def test_attachment_is_extracted_and_triaged(make_file, arch_fx):
    report = pipeline.triage(make_file("a.pdf", arch_fx.pdf_with_attachment()), Options())
    (child,) = report.children
    assert child["member"]["name"] == "invoice.exe"
    assert child["report"].file_type.kind == "text"
    assert any(f.id == "pdf.embedded_executable" for f in report.findings())
    assert report.verdict["rule"] == "V-MAL-06"


def test_flate_bomb_declared_size_is_refused(make_file, arch_fx, tmp_path):
    limits = Limits(max_member_size=1024 * 1024)
    r = analyze(make_file("b.pdf", arch_fx.pdf_flate_bomb(8 * 1024 * 1024)), tmp_path, limits)
    assert any("Attachment zeros.bin" in n and "per-member limit" in n for n in r.not_checked)
    assert list((tmp_path / "x").iterdir()) == []


def test_flate_bomb_lying_about_its_size_is_stopped(make_file, arch_fx, tmp_path):
    limits = Limits(max_member_size=1024 * 1024)
    data = arch_fx.pdf_flate_bomb(8 * 1024 * 1024, declared=100)
    r = analyze(make_file("b.pdf", data), tmp_path, limits)
    assert r.status == Status.PARTIAL
    assert any("zeros.bin" in e for e in r.errors)  # pypdf's limit or ours stopped it
    assert list((tmp_path / "x").iterdir()) == []  # nothing left behind
    assert any("Attachment zeros.bin" in n for n in r.not_checked)


def test_uri_links(make_file, arch_fx):
    report = pipeline.triage(make_file("u.pdf", arch_fx.pdf_uri()), Options())
    assert "https://login.example.com/verify" in {i["raw"] for i in report.indicators}


def test_broken_pdf_fails_loudly(make_file, tmp_path):
    r = analyze(make_file("x.pdf", b"%PDF-1.7\n1 0 obj << /JS (app.alert(1)) >>\ngarbage"),
                tmp_path)
    assert r.data["keywords"].get("/JS") == 1
    assert r.status in (Status.OK, Status.PARTIAL)
    assert "pdf.hidden_javascript" in ids(r) or r.errors


def test_jbig2_decoder_is_disabled(monkeypatch, make_file, arch_fx, tmp_path):
    seen = {}
    import pypdf

    real = pypdf.apply_configuration

    def spy(*args, **kwargs):
        seen.update(kwargs)
        return real(*args, **kwargs)

    monkeypatch.setattr(pypdf, "apply_configuration", spy)
    analyzer = next(a for a in registry() if a.name == "pdf")
    path = make_file("p.pdf", arch_fx.pdf_plain())
    runner.run_analyzer(analyzer, Context(path, identify(path), Options(), 0), isolate=False)
    assert "jbig2dec_binary" in seen and seen["jbig2dec_binary"] is None
