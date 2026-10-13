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


# M5 benign corpus 2: large legitimate scripts ----------------------------------------

def _repeat(n_kib: int, block: str) -> bytes:
    return (block * (n_kib * 1024 // len(block) + 1)).encode()[:n_kib * 1024]


def test_web_library_regex_exec_is_not_running_programs(make_file):
    # jQuery-like: RegExp.exec( throughout, an occasional joined literal, a computed
    # fromCharCode (jQuery decodes CSS escapes this way).
    plain = "var m = rquick.exec( selector );\n" * 40
    body = _repeat(200, plain + "var s = '[' + 'x' + ']';\n")
    body += b"var c = String.fromCharCode( high + 0x10000 );\n"
    r = analyze(make_file("lib.js", body))
    assert "script.js.shell" not in ids(r)
    assert "script.obfuscated" not in ids(r)


def test_wsh_run_and_exec_still_match(make_file):
    r = analyze(make_file("a.js", b"var sh = new ActiveXObject('WScript.Shell');\n"
                                  b"sh.Run('notepad.exe'); sh.Exec('cmd /c ver');\n"))
    assert "script.js.shell" in ids(r)


def test_admin_vbscript_with_a_few_chr_calls_is_not_obfuscated(make_file):
    # slmgr.vbs style: 140 KB of ordinary code with a Chr(34) every few dozen lines.
    plain = '    strOut = strOut & strName & vbCrLf\n' * 40
    body = _repeat(140, plain + 'WScript.Echo Chr(34) & strOut & Chr(34)\n')
    r = analyze(make_file("admin.vbs", b"Option Explicit\n" + body))
    assert r.data["obfuscation_shape"]["char_code_runs"] == 0
    assert "script.obfuscated" not in ids(r)


def test_padding_does_not_hide_heavy_char_code_obfuscation(make_file):
    # Density alone would be diluted by padding; the absolute count still catches it,
    # and the decoder reads the end of a large script, where the payload sits.
    payload = b"s = " + b" & ".join(b"Chr(%d)" % (65 + i % 26) for i in range(120)) + b"\n"
    padding = b"' " + b"x" * 78 + b"\n"
    r = analyze(make_file("p.vbs", b"Dim s\n" + padding * 20_000 + payload))
    assert "script.obfuscated" in ids(r)


def test_binary_stream_without_a_fetch_is_not_a_downloader(make_file):
    # slmgr.vbs: ADODB.Stream for files plus Eval to look up message strings.
    r = analyze(make_file("admin.vbs", b'Set oStream = CreateObject("ADODB.Stream")\n'
                                       b'GetResource = Eval(name)\n'))
    found = ids(r)
    assert "script.vbs.binary_write" in found and "script.download_execute" not in found


def test_fetch_save_and_run_is_still_a_downloader(make_file):
    r = analyze(make_file("dl.vbs", b'Set x = CreateObject("MSXML2.XMLHTTP")\n'
                                    b'Set s = CreateObject("ADODB.Stream")\n'
                                    b'CreateObject("WScript.Shell").Run "a.exe"\n'))
    assert ids(r)["script.download_execute"] == Severity.HIGH


def test_char_code_run_of_whitespace_is_not_obfuscation(make_file):
    # slmgr.vbs: its only char-code run builds line breaks and a tab.
    body = b'Const NL = Chr(13) & Chr(10) & Chr(9)\nWScript.Echo "x" & NL\n'
    r = analyze(make_file("a.vbs", body))
    assert r.data["obfuscation_shape"]["char_code_runs"] == 0
    assert "script.obfuscated" not in ids(r)


@pytest.mark.parametrize("code", [b"Chr(104) & Chr(116) & Chr(116) & Chr(112)",
                                  b"Chr(&H68) & Chr(&H74) & Chr(&H74)",
                                  b"ChrW(104) + ChrW(116) + ChrW(112)"])
def test_char_code_run_that_spells_text_is_obfuscation(make_file, code):
    r = analyze(make_file("a.vbs", b"s = " + code + b"\n"))
    assert "script.obfuscated" in ids(r)
