from __future__ import annotations

import json
from pathlib import Path

import pytest

from unopened import pipeline
from unopened.analyzers import Options
from unopened.indicators.allowlist import Allowlist
from unopened.indicators.defang import UNTOUCHED_KEYS
from unopened.indicators.extract import find_network_spans
from unopened.report import json_report, markdown

RAW_VALUES = [
    "malicious.example.com", "203.0.113.7", "admin@example.org", "198.51.100.23",
    "fileserver.example.net", "utf16.example.net", "http://", "https://",
]


def split_hunt(md):
    """(everything except the hunt section, the hunt section)."""
    if "## Hunt queries" not in md:
        return md, ""
    before, rest = md.split("## Hunt queries", 1)
    hunt, after = rest.split("## Analyzer status", 1)
    return before + "## Analyzer status" + after, hunt


def assert_no_live_indicators(md, report):
    body, hunt = split_hunt(md)
    assert find_network_spans(body) == [], find_network_spans(body)[:5]
    # The hunt section keeps query syntax (e.g. the ECS field file.name) intact but must
    # not contain any raw network indicator value.
    for ind in report.indicators:
        if ind["type"] in ("url", "domain", "ipv4", "ipv6", "email"):
            assert ind["raw"] not in hunt, ind["raw"]


@pytest.fixture
def report(make_file, fixtures):
    # A file name that is itself a domain must be defanged too.
    path = make_file("drop.example.com.exe", fixtures.suspicious_exe())
    return pipeline.triage(path, Options(allowlist=Allowlist.load()), isolate=False)


def test_markdown_sections(report):
    md = markdown.render(report)
    for heading in ["# Triage report:", "## Key findings", "## File identity", "## Hashes",
                    "## PE analysis", "### Sections", "### Imports", "## Indicators",
                    "## Analyzer status", "## Not checked"]:
        assert heading in md, heading
    assert "## Verdict" in md
    assert "Static analysis only" in md
    assert "Packer section name: UPX0" in md


def test_markdown_has_no_live_indicators(report):
    md = markdown.render(report)
    assert_no_live_indicators(md, report)
    for raw in RAW_VALUES:
        assert raw not in md, raw
    assert "hxxp://malicious.example[.]com/payload.bin" in md
    assert "drop.example[.]com.exe" in md or "drop.example.com[.]exe" in md


def _strings_outside_raw(node, path=()):
    if isinstance(node, dict):
        for k, v in node.items():
            if k in UNTOUCHED_KEYS:  # raw values, and the tool's own ids
                continue
            yield from _strings_outside_raw(k, path)
            yield from _strings_outside_raw(v, (*path, k))
    elif isinstance(node, list):
        for v in node:
            yield from _strings_outside_raw(v, path)
    elif isinstance(node, str):
        yield path, node


def test_json_raw_is_the_only_live_field(report):
    doc = json.loads(json_report.render(report))
    assert doc["schema_version"] == 2
    for path, text in _strings_outside_raw(doc):
        assert find_network_spans(text) == [], (path, text)
    raws = {i["raw"] for i in doc["indicators"]}
    assert "http://malicious.example.com/payload.bin" in raws
    assert doc["file"]["raw"]["name"] == "drop.example.com.exe"


def test_json_contents(report):
    doc = json.loads(json_report.render(report))
    assert set(doc["hashes"]) >= {"md5", "sha1", "sha256", "imphash"}
    assert doc["identification"]["kind"] == "pe"
    assert doc["verdict"]["value"] == "suspicious"
    assert doc["verdict"]["rule"] == "V-SUS-04"
    assert doc["analyzers"]["pe"]["status"] == "ok"
    assert any(n["check"].startswith("Capabilities") for n in doc["not_checked"])
    severities = [f["severity"] for f in doc["findings"]]
    order = ["high", "medium", "low", "info"]
    assert severities == sorted(severities, key=order.index)


def test_incomplete_check_is_prominent(make_file, monkeypatch):
    from unopened.analyzers import Analyzer
    from unopened.model import AnalyzerOutput

    def boom(c):
        raise ValueError("cannot parse")

    monkeypatch.setattr(pipeline, "registry", lambda: [
        Analyzer("strings", "Strings", lambda c: AnalyzerOutput(data={})),
        Analyzer("pe", "PE structure", boom),
    ])
    r = pipeline.triage(make_file("x.bin", b"abc"), Options(), isolate=False)
    md = markdown.render(r)
    assert "## Warning: some checks did not complete" in md
    assert "FAILED" in md
    assert "A check that did not complete is not a clean result." in md


def test_code_span_escaping():
    assert markdown.code("a|b") == "`a\\|b`"
    assert markdown.code("x`y") == "``x`y``"
    assert markdown.code("`edge`") == "`` `edge` ``"


def test_unknown_file_report(make_file):
    r = pipeline.triage(make_file("blob", b"\x00\x01\x02\xff" * 40), Options(), isolate=False)
    md = markdown.render(r)
    assert "Type-specific analysis" in md
    assert r.result("pe").status == "not_applicable"


RULES = Path(__file__).parent / "rules"


@pytest.mark.parametrize("name,build", [
    ("macro.docm", lambda o, lk, b: o.docm()),
    ("tmpl.docx", lambda o, lk, b: o.docx_remote_template()),
    ("dde.docx", lambda o, lk, b: o.docx_dde()),
    ("pad.lnk", lambda o, lk, b: lk.padded_cmd()),
    ("enc.lnk", lambda o, lk, b: lk.encoded_powershell()),
    ("s.exe", lambda o, lk, b: b.suspicious_exe()),
])
def test_new_sections_stay_defanged(make_file, office_fx, lnk_fx, fixtures, name, build):
    path = make_file(name, build(office_fx, lnk_fx, fixtures))
    options = Options(allowlist=Allowlist.load(), yara_rules=RULES / "yara",
                      capa_rules=RULES / "capa")
    report = pipeline.triage(path, options)
    md = markdown.render(report)
    assert_no_live_indicators(md, report)
    doc = json.loads(json_report.render(report))
    for p, text in _strings_outside_raw(doc):
        assert find_network_spans(text) == [], (p, text)
    expected = {".docm": "## Office document", ".docx": "## Office document",
                ".lnk": "## Shortcut (LNK)", ".exe": "## Capabilities (capa)"}
    assert expected[path.suffix] in md
    assert "## YARA" in md
