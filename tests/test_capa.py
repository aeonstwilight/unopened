from __future__ import annotations

from pathlib import Path

import pytest

from unopened import runner
from unopened.analyzers import Context, Options, registry
from unopened.identify import identify
from unopened.model import Severity, Status

pytest.importorskip("capa")
RULES = Path(__file__).parent / "rules" / "capa"

LIMITATION_RULE = """
rule:
  meta:
    name: (internal) fixture limitation
    namespace: internal/limitation/static
    description: This sample appears to be packed (fixture rule)
    authors:
      - unopened tests
    scopes:
      static: file
      dynamic: file
  features:
    - section: UPX0
"""


def run(path, rules=RULES):
    analyzer = next(a for a in registry() if a.name == "capa")
    ctx = Context(path, identify(path), Options(capa_rules=rules), path.stat().st_size)
    return runner.run_analyzer(analyzer, ctx)


def test_capability_with_attack_mapping(make_file, fixtures):
    r = run(make_file("s.exe", fixtures.suspicious_exe()))
    assert r.status == Status.OK, r.message
    (cap,) = r.data["capabilities"]
    assert cap["namespace"] == "host-interaction/process/inject"
    assert cap["attack"] == [{"tactic": "Defense Evasion", "technique": "Process Injection",
                              "id": "T1055"}]
    assert cap["mbc"] == ["Defense Evasion::Process Injection [E1055]"]
    titles = {f.title: f.severity for f in r.findings}
    # Tactic summaries are LOW (M5: they fired on nearly every signed admin tool).
    assert titles["capa: Defense Evasion (1 capability)"] == Severity.LOW


def test_no_match_on_benign(make_file, fixtures):
    r = run(make_file("a.exe", fixtures.benign_exe()))
    assert r.status == Status.OK
    assert r.data["capabilities"] == []
    assert [f.title for f in r.findings] == ["capa found no capabilities"]


def test_limitation_rule_is_reported(make_file, fixtures, tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "inject.yml").write_text((RULES / "inject-fixture.yml").read_text())
    (rules / "limitation.yml").write_text(LIMITATION_RULE)
    r = run(make_file("s.exe", fixtures.suspicious_exe()), rules)
    assert r.data["limitations"][0]["description"].startswith("This sample appears to be packed")
    assert "capa results are limited for this file" in [f.title for f in r.findings]
    assert any("packing" in n for n in r.not_checked)


def test_no_rules_is_unavailable(make_file, fixtures):
    r = run(make_file("a.exe", fixtures.benign_exe()), None)
    assert r.status == Status.UNAVAILABLE
    assert "--capa-rules" in r.message


def test_not_applicable_to_documents(make_file):
    assert run(make_file("a.txt", b"hello there plain text")).status == Status.NOT_APPLICABLE


def test_no_workspace_written_next_to_sample(make_file, fixtures):
    path = make_file("s.exe", fixtures.suspicious_exe())
    run(path)
    assert sorted(p.name for p in path.parent.iterdir()) == ["s.exe"]
