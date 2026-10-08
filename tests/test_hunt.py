from __future__ import annotations

import json

from unopened import hunt, pipeline
from unopened.analyzers import Options
from unopened.hunt import Values, quote


def values(**kw):
    base = dict(sha256=[], sha1=[], md5=[], file_names=[], domains=[], ips=[], urls=[],
                truncated=[])
    return Values(**(base | kw))


H = "a" * 64


def test_quoting_escapes_quotes_and_backslashes():
    assert quote('in"voice\\x.exe') == '"in\\"voice\\\\x.exe"'


def test_splunk_hash_queries():
    (raw, cim) = hunt.splunk(values(sha256=[H]), 30)
    assert raw["query"].startswith(f'index=* earliest=-30d ("{H}")')
    assert f'Filesystem.file_hash IN ("{H}") earliest=-30d' in cim["query"]


def test_splunk_network_queries():
    qs = {q["title"]: q["query"] for q in hunt.splunk(
        values(domains=["c2.example.com"], ips=["203.0.113.9"], urls=["http://x.example.com/a"]),
        7)}
    assert 'DNS.query IN ("c2.example.com") earliest=-7d' in qs[
        "DNS lookups of the domains (CIM Network_Resolution)"]
    assert 'All_Traffic.dest IN ("203.0.113.9")' in qs[
        "Connections to the IP addresses (CIM Network_Traffic)"]
    assert 'Web.url IN ("http://x.example.com/a")' in qs["Requests for the URLs (CIM Web)"]


def test_sentinel_hash_query():
    (q,) = hunt.sentinel(values(sha256=[H], md5=["b" * 32]), 14)
    text = q["query"]
    assert f'let sha256s = dynamic(["{H}"]);' in text
    assert 'let md5s = dynamic(["' + "b" * 32 + '"]);' in text
    assert "let sha1s = dynamic([]);" in text
    assert "| where Timestamp > ago(14d)" in text
    assert "EmailAttachmentInfo" in text


def test_sentinel_network_query():
    (q,) = hunt.sentinel(values(domains=["c2.example.com"], ips=["203.0.113.9"]), 30)
    assert 'let domains = dynamic(["c2.example.com"]);' in q["query"]
    assert "RemoteUrl has_any (domains)" in q["query"]
    assert "DnsEvents" in q["query"]


def test_elastic_queries():
    qs = hunt.elastic(values(sha1=["c" * 40], file_names=["run.lnk"], ips=["203.0.113.9"]), 30)
    text = "\n".join(q["query"] for q in qs)
    assert 'file.hash.sha1 : ("' + "c" * 40 + '")' in text
    assert 'file.name : ("run.lnk")' in text
    assert 'destination.ip : ("203.0.113.9")' in text
    assert all("time picker" in q["note"] for q in qs)


def test_no_values_no_queries():
    for _, _, fn in hunt.PLATFORMS:
        assert fn(values(), 30) == []


def test_collect_from_report_excludes_private_ips_and_caps(make_file, fixtures, monkeypatch):
    monkeypatch.setattr(hunt, "MAX_VALUES", 1)
    report = pipeline.triage(make_file("s.exe", fixtures.strings_exe()), Options(),
                             isolate=False)
    v = hunt.collect(report)
    assert v.sha256 == [report.hashes["sha256"]]
    assert v.ips == []  # the fixture's IPs are documentation ranges, tagged private/reserved
    assert v.domains and len(v.domains) == 1
    assert any(t.startswith("domains:") for t in v.truncated)


def test_members_contribute_hashes_and_names(make_file, arch_fx, lnk_fx):
    path = make_file("a.zip", arch_fx.zip_plain({"run.lnk": lnk_fx.encoded_powershell()}))
    report = pipeline.triage(path, Options())
    v = hunt.collect(report)
    assert v.file_names == ["a.zip", "run.lnk"]
    assert len(v.sha256) == 2


def test_markdown_keeps_syntax_and_defangs_values(make_file, fixtures):
    from unopened.report import markdown

    report = pipeline.triage(make_file("s.exe", fixtures.strings_exe()), Options(),
                             isolate=False)
    md = markdown.render(report)
    section = md.split("## Hunt queries", 1)[1].split("## Analyzer status", 1)[0]
    assert 'file.name : ("s.exe")' in section          # field name intact
    assert '"malicious.example[.]com"' in section      # value defanged
    assert "malicious.example.com" not in section
    assert report.hashes["sha256"] in section          # hashes paste-ready


def test_raw_queries_in_json_and_text(make_file, fixtures, tmp_path, capsys):
    from unopened import cli

    path = make_file("s.exe", fixtures.strings_exe())
    out = tmp_path / "out"
    assert cli.main(["triage", str(path), "--format", "both", "--out", str(out)]) == 0
    text = next(out.glob("*.hunt.txt")).read_text()
    assert '"malicious.example.com"' in text and "Raw (not defanged)" in text
    doc = json.loads(next(out.glob("*.json")).read_text())
    queries = doc["hunt"]["raw"]["queries"]["sentinel"]["queries"]
    assert any('"malicious.example.com"' in q["query"] for q in queries)


def test_no_hunt_flag(make_file, fixtures, capsys):
    from unopened import cli

    path = make_file("a.exe", fixtures.benign_exe())
    assert cli.main(["triage", str(path), "--no-hunt"]) == 0
    assert "## Hunt queries" not in capsys.readouterr().out
