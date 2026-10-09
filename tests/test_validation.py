"""The M5 validation harness, run only on synthetic benign fixtures."""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from unopened import validation
from unopened.validation import BEHAVIORS, Evidence, ExpectationError, load_expectations

ROOT = Path(__file__).resolve().parents[1]
HEADER = "sha256,name,label,expected_verdict,expected_behaviors,notes\n"


def write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def rows(out: Path) -> list[dict[str, str]]:
    with (out / "results.csv").open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


@pytest.fixture
def samples(tmp_path, fixtures, arch_fx):
    d = tmp_path / "samples"
    d.mkdir()
    (d / "plain.exe").write_bytes(fixtures.benign_exe())
    (d / "sus.exe").write_bytes(fixtures.suspicious_exe())
    (d / "labs.zip").write_bytes(arch_fx.zip_crypto({"Lab99-01.exe": fixtures.suspicious_exe()}))
    return d


def test_pma_expectations_file_is_valid():
    rows_ = load_expectations(ROOT / "validation" / "pma-labs.csv")
    assert len(rows_) >= 20
    assert all(r.label == "malicious" and r.behaviors for r in rows_)


def test_end_to_end(tmp_path, samples):
    exp = write(tmp_path / "exp.csv", HEADER
                + ",sus.exe,malicious,malicious|suspicious,"
                  "packed;injection;keylogging;anti_analysis;service,fixture\n"
                + ",Lab99-01.exe,malicious,malicious|suspicious,injection,inside a zip\n"
                + ",missing.exe,malicious,,,never present\n")
    out = tmp_path / "out"
    code = validation.main([str(samples), "--expectations", str(exp), "--out", str(out),
                            "--label", "benign"])
    assert code == 0
    by_sample = {r["sample"]: r for r in rows(out)}

    sus = by_sample["sus.exe"]
    assert sus["label"] == "malicious"
    assert sus["verdict"] in ("malicious", "suspicious") and sus["verdict_ok"] == "true"
    assert set(sus["found"].split(";")) == {"packed", "injection", "keylogging",
                                             "anti_analysis"}
    assert sus["missed"] == "service"

    # A sample inside an archive is matched by its own name and judged on its own report.
    lab = by_sample["Lab99-01.exe"]
    assert lab["file"] == "labs.zip" and lab["found"] == "injection"

    # Files without an expectation row take --label.
    assert by_sample["plain.exe"]["label"] == "benign"
    assert by_sample["plain.exe"]["verdict_ok"] == ""

    md = (out / "summary.md").read_text(encoding="utf-8")
    assert "## Behavior coverage" in md and "## Misses to explain" in md
    assert "## False positives on benign files" in md
    assert "missing.exe" in md  # expectation with no sample is listed


def test_outputs_never_carry_raw_indicators(tmp_path, samples):
    out = tmp_path / "out"
    assert validation.main([str(samples), "--out", str(out)]) == 0
    text = (out / "results.csv").read_text() + (out / "summary.md").read_text()
    # PLANTED_STRINGS in the PE fixture contain these; only labels may reach the outputs.
    for raw in ("198.51.100.23", "example.net", "http://", "hxxp", "digicert"):
        assert raw not in text
    assert not (out / "reports").exists()


def test_keep_reports(tmp_path, samples):
    out = tmp_path / "out"
    assert validation.main([str(samples), "--out", str(out), "--keep-reports"]) == 0
    assert len(list((out / "reports").glob("*.json"))) == 3


def test_reserved_triage_args_rejected(tmp_path, samples, capsys):
    for arg in ("--reputation", "--format=md", "--out"):
        assert validation.main([str(samples), "--", arg]) == 2
    assert "never part of validation" in capsys.readouterr().err


def test_triage_args_pass_through(tmp_path, samples):
    out = tmp_path / "out"
    assert validation.main([str(samples), "--out", str(out), "--",
                            "--min-string-length", "6"]) == 0
    assert "--min-string-length 6" in (out / "summary.md").read_text()


@pytest.mark.parametrize("body, message", [
    (",x.exe,maybe,,,\n", "label must be"),
    (",x.exe,malicious,bad,,\n", "unknown verdict"),
    (",x.exe,malicious,,teleport,\n", "unknown behavior"),
    (",,malicious,,,\n", "needs sha256 or name"),
])
def test_bad_expectations(tmp_path, body, message):
    with pytest.raises(ExpectationError, match=message):
        load_expectations(write(tmp_path / "e.csv", HEADER + body))


def test_untriageable_file_is_reported_not_fatal(tmp_path, fixtures):
    d = tmp_path / "s"
    d.mkdir()
    (d / "a.exe").write_bytes(fixtures.benign_exe())
    (d / "big.bin").write_bytes(b"x" * 2048)
    out = tmp_path / "out"
    assert validation.main([str(d), "--out", str(out), "--", "--max-size", "1800"]) == 1
    assert "big.bin" in (out / "summary.md").read_text()
    assert [r["sample"] for r in rows(out)] == ["a.exe"]


def test_every_behavior_has_a_working_test():
    empty = Evidence()
    for name, (title, test) in BEHAVIORS.items():
        assert title and test(empty) is False, name


def test_rpisec_expectations_file_is_valid():
    rows_ = load_expectations(ROOT / "validation" / "rpisec-labs.csv")
    assert len(rows_) >= 15
    assert all(r.name.endswith(".malware") for r in rows_)


def test_member_in_subfolder_matches_base_name_and_include_filter(tmp_path, fixtures, arch_fx):
    d = tmp_path / "Labs" / "Lab_01"
    d.mkdir(parents=True)
    (d / "Lab_01.zip").write_bytes(
        arch_fx.zip_crypto({"Lab_01/Lab_01-1.malware": fixtures.suspicious_exe()}))
    (d / "solution.md").write_text("# not a sample\n")
    exp = write(tmp_path / "e.csv", HEADER + ",Lab_01-1.malware,malicious,,injection,\n")
    out = tmp_path / "out"
    assert validation.main([str(tmp_path / "Labs"), "--expectations", str(exp), "--out",
                            str(out), "--include", "*.zip", "--label", "malicious"]) == 0
    got = rows(out)
    assert [r["file"] for r in got] == ["Lab_01/Lab_01.zip"]
    assert got[0]["found"] == "injection"
    assert "no matching sample" not in (out / "summary.md").read_text()
