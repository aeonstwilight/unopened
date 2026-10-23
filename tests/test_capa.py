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


# M6: rule cache and the file-scope fallback --------------------------------------------

def _slow_viv(monkeypatch, also_pefile=False):
    """Make full (vivisect) analysis hang so the timeout and fallback paths run."""
    import time

    import capa.loader

    real = capa.loader.get_extractor

    def slow(path, fmt, os_, backend, *args, **kwargs):
        if backend == capa.loader.BACKEND_VIV or also_pefile:
            time.sleep(60)
        return real(path, fmt, os_, backend, *args, **kwargs)

    monkeypatch.setattr(capa.loader, "get_extractor", slow)


def run_with(path, **timeouts):
    analyzer = next(a for a in registry() if a.name == "capa")
    opts = Options(capa_rules=RULES, timeouts={"capa": 300.0, "capa_file_scope": 60.0,
                                               **timeouts})
    return runner.run_analyzer(analyzer, Context(path, identify(path), opts,
                                                 path.stat().st_size))


def test_timeout_falls_back_to_file_scope_rules(make_file, fixtures, monkeypatch):
    _slow_viv(monkeypatch)
    r = run_with(make_file("s.exe", fixtures.suspicious_exe()), capa=1.0)
    assert r.status == Status.PARTIAL
    assert r.data["fallback"] == "capa_file_scope" and r.data["file_scope_only"]
    assert r.data["backend"] == "pefile"
    # the fixture rule is file-scoped (imports), so the fallback still finds it
    assert [c["namespace"] for c in r.data["capabilities"]] == ["host-interaction/process/inject"]
    assert "timed out" in r.message or "did not finish" in r.message
    assert r.errors[0].startswith("full analysis")
    assert any("Function-level capabilities" in n for n in r.not_checked)
    assert {f.source for f in r.findings} == {"capa"}


def test_fallback_failure_is_still_a_timeout(make_file, fixtures, monkeypatch):
    _slow_viv(monkeypatch, also_pefile=True)
    r = run_with(make_file("s.exe", fixtures.suspicious_exe()), capa=1.0, capa_file_scope=1.0)
    assert r.status == Status.TIMEOUT
    assert "fallback also failed" in r.message


def test_rule_cache_is_reused(tmp_path, monkeypatch):
    import capa.rules

    from unopened.analyzers.capa_analyzer import load_rules

    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    first = load_rules(RULES)
    calls = []
    real = capa.rules.Rule.from_yaml
    monkeypatch.setattr(capa.rules.Rule, "from_yaml",
                        staticmethod(lambda *a, **k: calls.append(1) or real(*a, **k)))
    second = load_rules(RULES)
    assert calls == []  # loaded from the cache, not re-parsed
    assert sorted(second.rules) == sorted(first.rules)


def test_unwritable_rule_cache_is_not_an_error(tmp_path, monkeypatch):
    import capa.rules.cache

    from unopened.analyzers.capa_analyzer import load_rules

    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    real = capa.rules.cache.cache_ruleset
    state = {"first": True}

    def refuse_once(cache_dir, ruleset):
        if state.pop("first", False):
            raise PermissionError("read-only cache directory")
        return real(cache_dir, ruleset)

    monkeypatch.setattr(capa.rules.cache, "cache_ruleset", refuse_once)
    rules = load_rules(RULES)
    assert rules.rules  # parsed despite the cache failure
