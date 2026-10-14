from __future__ import annotations

import base64

import pytest

from unopened.deobfuscate import decode_base64_text, deobfuscate, find_encoded_command


def b64u16(text):
    return base64.b64encode(text.encode("utf-16-le")).decode()


@pytest.mark.parametrize(("source", "expected", "technique"), [
    (f"powershell -enc {b64u16('Write-Host fixture')}", "Write-Host fixture", "base64"),
    (f"[Convert]::FromBase64String('{b64u16('Write-Host fixture')}')", "Write-Host fixture",
     "base64"),
    ("atob('V3JpdGUtSG9zdCBmaXh0dXJl')", "Write-Host fixture", "base64"),
    ("$c = [char]73+[char]69+[char]88", "'IEX'", "char codes"),
    ("[char]0x41", "'A'", "char codes"),
    ("String.fromCharCode(72,105)", '"Hi"', "char codes"),
    ("String.fromCharCode(0x48,0x69)", '"Hi"', "char codes"),
    ('x = Chr(72) & ChrW(&H69)', '"Hi"', "char codes"),
    ("-join ((87,114,105,116,101) | %{[char]$_})", "'Write'", "char codes"),
    ("'ht' + 'tp://' + 'x.example.com'", "'http://x.example.com'", "string concatenation"),
    ('"a" & "b" & "c"', '"abc"', "string concatenation"),
])
def test_transformations(source, expected, technique):
    result = deobfuscate(source)
    assert expected in result.text
    assert technique in result.techniques()


def test_layers_compose():
    # char codes produce literals, which concatenation then joins
    result = deobfuscate("[char]104+[char]105+'!'")
    assert "'hi!'" in result.text
    assert [layer.technique for layer in result.layers] == ["char codes", "string concatenation"]


def test_nested_base64():
    inner = b64u16("Write-Host deep")
    outer = b64u16(f"powershell -enc {inner}")
    result = deobfuscate(f"powershell -enc {outer}")
    assert "Write-Host deep" in result.text
    assert sum(x.count for x in result.layers if x.technique == "base64") == 2


def test_plain_text_unchanged():
    text = "Get-ChildItem -Path . | Sort-Object Length\n"
    result = deobfuscate(text)
    assert result.text == text and not result.changed


def test_number_arrays_need_char_context():
    assert not deobfuscate("$ports = @(80, 443, 8080, 8443)").changed


def test_rounds_and_size_are_bounded():
    blob = b64u16("A" * 100)
    for _ in range(10):
        blob = b64u16(f"powershell -enc {blob}")
    result = deobfuscate(f"powershell -enc {blob}", max_rounds=3)
    assert len(result.layers) <= 3 * 3
    big = deobfuscate("'a' + 'b'" * 10, max_chars=20)
    assert big.truncated and len(big.text) <= 20


def test_execution_policy_is_not_encoded_command():
    assert find_encoded_command("-ExecutionPolicy Bypass -File x.ps1 AAAAAAAAAAAAAAAAAAAA") is None


def test_undecodable_base64():
    assert decode_base64_text("!!!notbase64!!!") is None
    assert decode_base64_text(base64.b64encode(bytes(range(256))).decode()) is None  # binary


def test_batch_variable_expansion():
    from unopened.deobfuscate import deobfuscate
    text = 'set "a=powershell"\r\nset b=calc\r\n%a:~0,5%%a:~5% -c %b%\r\n%a:~-5% %a:~0,-5%\r\n'
    r = deobfuscate(text, language="batch")
    assert "powershell -c calc" in r.text
    assert "shell power" in r.text
    assert "batch variables" in r.techniques()
    # Other languages: % is not a variable sigil.
    assert "batch variables" not in deobfuscate(text).techniques()


def test_batch_variable_set_twice_is_not_expanded():
    from unopened.deobfuscate import deobfuscate
    r = deobfuscate("set a=one\r\nset a=two\r\necho %a%\r\n", language="batch")
    assert "%a%" in r.text
