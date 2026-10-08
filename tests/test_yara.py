from __future__ import annotations

from pathlib import Path

import pytest

from unopened import runner
from unopened.analyzers import Context, Options, registry
from unopened.identify import identify
from unopened.model import Severity, Status

pytest.importorskip("yara")
RULES = Path(__file__).parent / "rules" / "yara"
BROKEN = Path(__file__).parent / "rules" / "yara_broken.yar"


def scan(path, rules):
    analyzer = next(a for a in registry() if a.name == "yara")
    ctx = Context(path, identify(path), Options(yara_rules=rules), path.stat().st_size)
    return runner.run_analyzer(analyzer, ctx)  # in a worker, as in production


def test_eicar_matches(make_file, fixtures):
    r = scan(make_file("eicar.com", fixtures.EICAR), RULES)
    assert r.status == Status.OK
    (m,) = r.data["matches"]
    assert (m["rule"], m["namespace"], m["tags"]) == ("EICAR_Test_File", "eicar", ["test"])
    assert m["strings"][0]["instances"][0]["data"] == "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    assert r.findings[0].severity == Severity.HIGH  # from meta severity = "high"


def test_namespace_from_subdirectory_and_wide_strings(make_file, fixtures):
    r = scan(make_file("s.exe", fixtures.strings_exe()), RULES)
    (m,) = r.data["matches"]
    assert m["namespace"] == "sub/fixture_url"
    by_id = {s["identifier"]: s for s in m["strings"]}
    assert by_id["$wide"]["instances"][0]["data"] == "utf-16: utf16.example.net"
    assert r.findings[0].severity == Severity.MEDIUM  # score 50


def test_clean_file_has_no_matches(make_file, fixtures):
    r = scan(make_file("a.exe", fixtures.benign_exe()), RULES)
    assert r.status == Status.OK and r.data["matches"] == [] and r.findings == []
    assert r.data["rule_count"] == 2


def test_no_rules_configured_is_unavailable(make_file):
    r = scan(make_file("a.txt", b"hello world text"), None)
    assert r.status == Status.UNAVAILABLE
    assert "--yara-rules" in r.message


def test_missing_rules_path_is_unavailable(make_file, tmp_path):
    r = scan(make_file("a.txt", b"hello world text"), tmp_path / "nope")
    assert r.status == Status.UNAVAILABLE


def test_compile_error_is_partial_and_others_still_run(make_file, fixtures, tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "eicar.yar").write_text((RULES / "eicar.yar").read_text())
    (rules / "broken.yar").write_text(BROKEN.read_text())
    r = scan(make_file("eicar.com", fixtures.EICAR), rules)
    assert r.status == Status.PARTIAL
    assert any("broken" in e for e in r.errors)
    assert [m["rule"] for m in r.data["matches"]] == ["EICAR_Test_File"]
    assert any("failed to compile" in n for n in r.not_checked)


def test_all_rules_broken_is_error(make_file):
    r = scan(make_file("a.txt", b"hello world text"), BROKEN)
    assert r.status == Status.ERROR
    assert "none of the 1 YARA rule file(s) compiled" in r.message


def test_externals_available_to_rules(make_file, tmp_path):
    rule = tmp_path / "ext.yar"
    rule.write_text('rule ByName { condition: filename matches /invoice/ and extension == ".js" }')
    r = scan(make_file("invoice.js", b"var x = 1;"), rule)
    assert [m["rule"] for m in r.data["matches"]] == ["ByName"]
