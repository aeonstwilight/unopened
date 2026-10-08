from __future__ import annotations

import pytest

from unopened.indicators.defang import defang, defang_text, defang_tree
from unopened.indicators.extract import find_network_spans


@pytest.mark.parametrize(("kind", "value", "expected"), [
    ("url", "http://example.com/a.b", "hxxp://example[.]com/a.b"),
    ("url", "https://sub.example.com:8443/x", "hxxps://sub.example[.]com:8443/x"),
    ("url", "HTTP://EXAMPLE.COM", "HXXP://EXAMPLE[.]COM"),
    ("url", "ftp://user@files.example.net/", "fxp://user[@]files.example[.]net/"),
    ("url", "http://[2001:db8::1]:80/", "hxxp://[2001[:]db8[:][:]1]:80/"),
    ("domain", "example.com", "example[.]com"),
    ("domain", "a.b.example.com", "a.b.example[.]com"),
    ("ipv4", "10.0.0.1", "10.0.0[.]1"),
    ("ipv6", "2001:db8::1", "2001[:]db8[:][:]1"),
    ("email", "user@example.com", "user[@]example[.]com"),
    ("unc_path", "\\\\srv.example.com\\share", "\\\\srv.example[.]com\\share"),
    ("file_path", "C:\\x\\y.exe", "C:\\x\\y.exe"),
])
def test_defang(kind, value, expected):
    assert defang(kind, value) == expected


def test_defang_text_catches_everything():
    text = ("Beacon to http://evil.example.com/a, fallback 203.0.113.5, "
            "mail ops@example.org, host files.example.net, v6 2001:db8:1::2")
    out = defang_text(text)
    assert find_network_spans(out) == []
    assert "hxxp://evil.example[.]com/a" in out
    assert "203.0.113[.]5" in out


def test_defang_text_is_idempotent():
    once = defang_text("see http://example.com and example.org")
    assert defang_text(once) == once


def test_defang_text_also_catches_noise_like_names():
    # Extraction drops "setup.zip" as a probable file name; defanging still neuters it.
    assert defang_text("setup.zip") == "setup[.]zip"


def test_defang_tree_keeps_raw():
    tree = {"value": "http://example.com", "raw": "http://example.com",
            "nested": [{"context": "x 192.0.2.1 y", "raw": {"name": "a.example.com"}}]}
    out = defang_tree(tree)
    assert out["value"] == "hxxp://example[.]com"
    assert out["raw"] == "http://example.com"
    assert out["nested"][0]["context"] == "x 192.0.2[.]1 y"
    assert out["nested"][0]["raw"] == {"name": "a.example.com"}
