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


def test_full_import_list_counts_for_behaviors(tmp_path, fixtures):
    # Found in M5 validation: CopyFileA is in no import category, so a harness that read
    # only the categorised imports could never surface file_write from imports.
    spec = fixtures.PESpec(imports={"kernel32.dll": ["CopyFileA", "ExitProcess"]})
    d = tmp_path / "s"
    d.mkdir()
    (d / "copy.exe").write_bytes(fixtures.build_pe(spec))
    exp = write(tmp_path / "e.csv", HEADER + ",copy.exe,malicious,,file_write,\n")
    out = tmp_path / "out"
    assert validation.main([str(d), "--expectations", str(exp), "--out", str(out)]) == 0
    assert rows(out)[0]["found"] == "file_write"


def _verdicts(out):
    return sorted((r["file"], r["sample"], r["verdict"], r["found"]) for r in rows(out))


def test_parallel_jobs_match_sequential(tmp_path, samples):
    seq, par = tmp_path / "seq", tmp_path / "par"
    assert validation.main([str(samples), "--out", str(seq)]) == 0
    assert validation.main([str(samples), "--out", str(par), "--jobs", "2"]) == 0
    assert _verdicts(seq) == _verdicts(par)


def test_resume_skips_files_already_done(tmp_path, samples, capsys):
    out = tmp_path / "out"
    assert validation.main([str(samples), "--out", str(out)]) == 0
    full = _verdicts(out)
    # Simulate an interrupted run: keep only the first file's rows.
    lines = (out / "results.csv").read_text().splitlines()
    first = lines[1].split(",")[0]
    (out / "results.csv").write_text(
        "\n".join([lines[0]] + [ln for ln in lines[1:] if ln.startswith(first + ",")]) + "\n")
    capsys.readouterr()
    assert validation.main([str(samples), "--out", str(out), "--resume"]) == 0
    err = capsys.readouterr().err
    assert "resuming: 1 file(s) already done" in err
    assert f"triage {first}" not in err
    assert _verdicts(out) == full


def test_results_are_written_as_files_finish(tmp_path, samples, monkeypatch):
    out = tmp_path / "out"
    seen = []
    real = validation.append_csv

    def spy(rs, path):
        real(rs, path)
        seen.append(len(path.read_text().splitlines()))
    monkeypatch.setattr(validation, "append_csv", spy)
    assert validation.main([str(samples), "--out", str(out)]) == 0
    assert seen == sorted(seen) and len(seen) == 3  # one append per file, growing


def test_resume_survives_a_row_cut_off_by_a_crash(tmp_path, samples, capsys):
    # M5 corpus 2: a VM stall killed the run while it wrote a row, leaving a cut-off last
    # line (and NUL bytes); --resume then crashed reading it.
    out = tmp_path / "out"
    assert validation.main([str(samples), "--out", str(out)]) == 0
    full = _verdicts(out)
    lines = (out / "results.csv").read_text().splitlines()
    first, second = lines[1], lines[2]
    cut = second[: len(second) // 3]  # the second file's row, cut off mid-write
    (out / "results.csv").write_text("\n".join([lines[0], first]) + "\n" + cut + "\0\0")
    capsys.readouterr()
    assert validation.main([str(samples), "--out", str(out), "--resume"]) == 0
    err = capsys.readouterr().err
    assert "resuming: 1 file(s) already done; dropped 1 incomplete row(s)" in err
    assert f"triage {second.split(',')[0]}" in err  # the cut-off file is redone
    assert _verdicts(out) == full
    text = (out / "results.csv").read_text()
    assert "\0" not in text and len(text.splitlines()) == len(lines)


def test_fallback_is_labeled_as_a_timeout():
    from unopened.validation import _incomplete

    report = {"analyzers": {
        "capa": {"status": "partial", "data": {"fallback": "capa_file_scope"}},
        "office": {"status": "partial", "data": {}},
        "yara": {"status": "ok", "data": {}},
    }, "members": []}
    assert _incomplete(report) == ["capa:timeout-fallback", "office:partial"]
