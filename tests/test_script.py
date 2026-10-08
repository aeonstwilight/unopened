from __future__ import annotations

import pytest

from unopened import pipeline, runner
from unopened.analyzers import Context, Options, registry
from unopened.identify import identify
from unopened.model import Severity, Status


def analyze(path):
    analyzer = next(a for a in registry() if a.name == "script")
    ctx = Context(path, identify(path), Options(), path.stat().st_size)
    return runner.run_analyzer(analyzer, ctx)


def ids(r):
    return {f.id: f.severity for f in r.findings}


@pytest.mark.parametrize(("name", "attr", "expected"), [
    ("dl.ps1", "PS_DOWNLOADER", {"script.download_execute", "script.ps.invoke_expression",
                                 "script.ps.download", "script.obfuscated"}),
    ("enc.ps1", "PS_ENCODED", {"script.download_execute", "script.ps.hidden_window",
                               "script.obfuscated"}),
    ("d.js", "JS_DROPPER", {"script.download_execute", "script.js.activex",
                            "script.js.download", "script.obfuscated"}),
    ("c.vbs", "VBS_CHR", {"script.vbs.shell", "script.obfuscated"}),
    ("c.bat", "BAT_CERTUTIL", {"script.bat.certutil", "script.bat.run_key"}),
])
def test_malicious_shapes(make_file, arch_fx, name, attr, expected):
    r = analyze(make_file(name, getattr(arch_fx, attr)))
    assert r.status == Status.OK
    assert expected <= set(ids(r)), ids(r)


@pytest.mark.parametrize(("name", "attr"), [("ok.ps1", "PS_BENIGN"), ("ok.bat", "BAT_BENIGN")])
def test_benign_scripts_are_quiet(make_file, arch_fx, name, attr):
    r = analyze(make_file(name, getattr(arch_fx, attr)))
    assert [f for f in r.findings if f.severity != Severity.INFO] == []


def test_decoded_urls_become_indicators(make_file, arch_fx):
    report = pipeline.triage(make_file("enc.ps1", arch_fx.PS_ENCODED), Options())
    urls = {i["raw"]: i for i in report.indicators if i["type"] == "url"}
    assert "script" in urls["http://enc.example.com/a"]["sources"]
    report = pipeline.triage(make_file("d.js", arch_fx.JS_DROPPER), Options())
    assert "http://js.example.com/a.exe" in {i["raw"] for i in report.indicators}


def test_deobfuscated_text_is_reported(make_file, arch_fx):
    r = analyze(make_file("dl.ps1", arch_fx.PS_DOWNLOADER))
    assert "'IEX'" in r.data["deobfuscated"]
    assert "http://dl.example.com/stage2.ps1" in r.data["deobfuscated"]


def test_long_line(make_file):
    r = analyze(make_file("x.ps1", b"$a = '" + b"A" * 3000 + b"'\nWrite-Host $a\n$b = 1\n"))
    assert "script.long_line" in ids(r)
