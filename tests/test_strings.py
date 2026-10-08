from __future__ import annotations

from unopened import runner
from unopened.analyzers import Context, Options, registry
from unopened.analyzers.strings import iter_strings
from unopened.identify import identify
from unopened.indicators.allowlist import Allowlist
from unopened.model import Status


def test_ascii_and_utf16():
    data = b"\x00\x01hello world\x00\xff" + "wide string".encode("utf-16-le") + b"\x00\x00ab\x00"
    found = list(iter_strings(data, 5))
    assert (2, "ascii", "hello world") in found
    assert any(enc == "utf-16le" and text == "wide string" for _, enc, text in found)
    assert not any(text == "ab" for _, _, text in found)


def test_min_length():
    data = b"abcd\x00abcdef\x00"
    assert [t for _, _, t in iter_strings(data, 5)] == ["abcdef"]
    assert [t for _, _, t in iter_strings(data, 4)] == ["abcd", "abcdef"]


def run(path, **opts):
    analyzer = next(a for a in registry() if a.name == "strings")
    options = Options(allowlist=opts.pop("allowlist", Allowlist.load()), **opts)
    ctx = Context(path, identify(path), options, path.stat().st_size)
    return runner.run_analyzer(analyzer, ctx, isolate=False)


def test_indicators_from_pe(make_file, fixtures):
    r = run(make_file("s.exe", fixtures.strings_exe()))
    assert r.status == Status.OK
    raw = {(i["type"], i["raw"]) for i in r.data["indicators"]}
    assert ("url", "http://malicious.example.com/payload.bin") in raw
    assert ("url", "https://203.0.113.7:8443/gate.php?id=1") in raw
    assert ("domain", "malicious.example.com") in raw
    assert ("ipv4", "203.0.113.7") in raw
    assert ("ipv4", "198.51.100.23") in raw
    assert ("email", "admin@example.org") in raw
    assert ("file_path", "C:\\Users\\Public\\Documents\\update.exe") in raw
    assert ("unc_path", "\\\\fileserver.example.net\\share\\tools") in raw
    assert ("url", "http://utf16.example.net/beacon") in raw
    assert ("registry_key", "Software\\Microsoft\\Windows\\CurrentVersion\\Run") in raw
    # The CA revocation URL is allowlisted: hidden, but counted.
    assert not any("digicert" in v for _, v in raw)
    assert sorted(k for k, _ in r.data["allowlisted"]) == ["domain", "url"]
    utf16 = next(i for i in r.data["indicators"] if i["raw"] == "http://utf16.example.net/beacon")
    assert utf16["encodings"] == ["utf-16le"]


def test_defanged_value_alongside_raw(make_file, fixtures):
    r = run(make_file("s.exe", fixtures.strings_exe()))
    url = next(i for i in r.data["indicators"] if i["type"] == "url")
    assert url["value"] == "hxxp://malicious.example[.]com/payload.bin"
    assert url["raw"] == "http://malicious.example.com/payload.bin"


def test_findings(make_file, fixtures):
    from unopened.analyzers.strings import summarize_indicators

    r = run(make_file("s.exe", fixtures.strings_exe()))
    titles = [f.title for f in summarize_indicators(r.data["indicators"])]
    assert "Network indicators found" in titles
    assert "References registry locations used for persistence" in titles


def test_string_cap_is_reported(make_file):
    data = b"\x00".join(b"string%05d" % i for i in range(500))
    r = run(make_file("many.bin", data), max_strings=100)
    assert r.data["truncated"] is True
    assert any("100" in n for n in r.not_checked)


def test_indicator_cap_is_reported(make_file):
    data = b"\x00".join(b"http://host%d.example.com/" % i for i in range(50))
    r = run(make_file("many.bin", data), max_indicators=10)
    assert len(r.data["indicators"]) == 10
    assert any("Indicators beyond" in n for n in r.not_checked)


def test_repeat_counts(make_file):
    data = b"\x00".join([b"http://repeat.example.com/x"] * 3)
    r = run(make_file("r.bin", data), allowlist=Allowlist())
    url = next(i for i in r.data["indicators"] if i["type"] == "url")
    assert url["count"] == 3 and url["first_offset"] == 0
