from __future__ import annotations

import pytest

from unopened.indicators.allowlist import Allowlist, AllowlistError
from unopened.indicators.extract import extract, known_tlds


def kinds(text):
    return {(h.kind, h.value) for h in extract(text)}


def test_tld_list_loaded():
    tlds = known_tlds()
    assert {"com", "org", "net", "uk", "io"} <= tlds
    assert "dll" not in tlds and "exe" not in tlds


@pytest.mark.parametrize(("text", "expected"), [
    ("GET http://example.com/a/b?c=d HTTP/1.1", ("url", "http://example.com/a/b?c=d")),
    ("(see https://example.org/x).", ("url", "https://example.org/x")),
    ("ftp://files.example.net/pub", ("url", "ftp://files.example.net/pub")),
    ("connect to update.example.com now", ("domain", "update.example.com")),
    ("ADDR 192.0.2.44:443", ("ipv4", "192.0.2.44")),
    ("v6 2001:db8:0:1::10 here", ("ipv6", "2001:db8:0:1::10")),
    ("mail Someone@Example.org please", ("email", "someone@example.org")),
    ("C:\\Windows\\Temp\\a b\\x.exe", ("file_path", "C:\\Windows\\Temp\\a b\\x.exe")),
    ("%APPDATA%\\Microsoft\\x.dll", ("file_path", "%APPDATA%\\Microsoft\\x.dll")),
    ("\\\\host.example.com\\c$\\x", ("unc_path", "\\\\host.example.com\\c$\\x")),
    ("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
     ("registry_key", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce")),
    ("HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\x",
     ("registry_key", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\x")),
])
def test_positives(text, expected):
    assert expected in kinds(text)


def test_url_host_also_reported():
    found = kinds("http://203.0.113.9/x and https://sub.example.com:8080/")
    assert ("ipv4", "203.0.113.9") in found
    assert ("domain", "sub.example.com") in found


@pytest.mark.parametrize("text", [
    "kernel32.dll",
    "LoadLibraryA GetProcAddress",
    "1.2.3.999",
    "01.02.03.04",
    "version 1.2.3.4.5",
    "System.Security.Cryptography",
    "Microsoft.Win32.Registry",
    "setup.zip",
    "script.py",
    "button.click()",
    "12:30:45",
    "std::vector",
    "icon@2x.png",
    "C:\\",
])
def test_negatives(text):
    network = {k for k, _ in kinds(text)} & {"url", "domain", "ipv4", "ipv6", "email", "file_path"}
    assert not network, kinds(text)


def test_bare_domain_on_extension_like_tld_kept_in_url():
    assert ("url", "http://files.example.zip/x") in kinds("http://files.example.zip/x")


def test_ip_tags():
    tags = {h.value: h.tags for h in extract("8.8.8.8 10.1.2.3 127.0.0.1") if h.kind == "ipv4"}
    assert tags["8.8.8.8"] == ("public",)
    assert tags["10.1.2.3"] == ("private_or_reserved",)
    assert tags["127.0.0.1"] == ("loopback",)


def test_version_like_ip_is_tagged():
    (hit,) = [h for h in extract("1.0.0.0") if h.kind == "ipv4"]
    assert "possible_version_number" in hit.tags


def test_persistence_registry_tag():
    (hit,) = extract("HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon")
    assert any(t.startswith("persistence:") for t in hit.tags)


def test_browser_helper_object_is_persistence():
    # Found in M5 validation: a BHO registration path without a hive prefix was extracted
    # but not recognized as persistence.
    (hit,) = extract("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\"
                     "Browser Helper Objects\\{00000000-0000-0000-0000-000000000000}")
    assert hit.kind == "registry_key"
    assert any("Browser Helper Object" in t for t in hit.tags)


def test_trailing_punctuation_and_brackets():
    assert ("url", "http://example.com/a(b)") in kinds("x http://example.com/a(b), y")
    assert ("url", "http://example.com/a") in kinds("(http://example.com/a)")


# Allowlist ---------------------------------------------------------------------------

def test_default_allowlist():
    al = Allowlist.load()
    assert al.allows("domain", "crl3.digicert.com")
    assert al.allows("url", "http://www.w3.org/2000/09/xmldsig#")
    assert al.allows("domain", "schemas.microsoft.com")
    assert not al.allows("domain", "example.com")
    assert not al.allows("domain", "notdigicert.com")


def test_allowlist_kinds():
    al = Allowlist.from_dict({
        "domains": {"exact": ["only.example.com"], "suffix": ["corp.example"]},
        "urls": {"prefix": ["https://intranet.example.net/"]},
        "ips": {"cidr": ["10.0.0.0/8", "2001:db8::/32"]},
        "emails": {"exact": ["soc@example.org"]},
        "paths": {"prefix": ["C:\\Program Files\\"]},
        "registry": {"prefix": ["HKLM\\Software\\Vendor"]},
    })
    assert al.allows("domain", "only.example.com")
    assert not al.allows("domain", "sub.only.example.com")
    assert al.allows("domain", "a.b.corp.example") and al.allows("domain", "corp.example")
    assert al.allows("url", "HTTPS://intranet.example.net/page")
    assert al.allows("url", "http://host.corp.example/x")
    assert al.allows("ipv4", "10.20.30.40") and not al.allows("ipv4", "192.0.2.1")
    assert al.allows("ipv6", "2001:db8::5")
    assert al.allows("email", "SOC@example.org") and al.allows("email", "x@host.corp.example")
    assert al.allows("file_path", "c:\\program files\\app\\a.exe")
    assert al.allows("registry_key", "HKLM\\SOFTWARE\\Vendor\\Key")


@pytest.mark.parametrize(("doc", "message"), [
    ({"domainz": {}}, "unknown section"),
    ({"ips": {"cidr": ["not-an-ip"]}}, "bad IP"),
    ({"domains": {"exact": "example.com"}}, "must be a list"),
])
def test_bad_allowlist_fails_loudly(doc, message):
    with pytest.raises(AllowlistError, match=message):
        Allowlist.from_dict(doc)


def test_bad_toml_fails_loudly(tmp_path):
    p = tmp_path / "a.toml"
    p.write_text("[domains\nexact = [", encoding="utf-8")
    with pytest.raises(AllowlistError, match="not valid TOML"):
        Allowlist.load(p)
