from __future__ import annotations

import importlib.util
import json

import pytest

from unopened import cli


def test_markdown_to_stdout(make_file, fixtures, capsys):
    path = make_file("a.exe", fixtures.benign_exe())
    assert cli.main(["triage", str(path)]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert out.startswith("# Triage report: `a.exe`")


def test_json_to_stdout(make_file, fixtures, capsys):
    path = make_file("a.exe", fixtures.strings_exe())
    assert cli.main(["triage", str(path), "--format", "json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["identification"]["kind"] == "pe"
    assert doc["indicators"]


def test_both_to_directory(make_file, fixtures, tmp_path):
    path = make_file("a.exe", fixtures.benign_exe())
    out = tmp_path / "reports"
    assert cli.main(["triage", str(path), "--format", "both", "--out", str(out)]) == 0
    files = sorted(p.name.split(".", 1)[1] for p in out.iterdir())
    assert files == ["hunt.txt", "json", "md"]
    sha = json.loads(next(out.glob("*.json")).read_text())["hashes"]["sha256"]
    assert (out / f"{sha}.md").exists()


def test_both_needs_out(make_file, fixtures, capsys):
    path = make_file("a.exe", fixtures.benign_exe())
    assert cli.main(["triage", str(path), "--format", "both"]) == cli.EXIT_USAGE
    assert "--out" in capsys.readouterr().err


def test_missing_file(tmp_path, capsys):
    assert cli.main(["triage", str(tmp_path / "nope")]) == cli.EXIT_INPUT
    assert "cannot read" in capsys.readouterr().err


def test_directory_needs_out(tmp_path, capsys):
    assert cli.main(["triage", str(tmp_path)]) == cli.EXIT_USAGE
    assert "needs --out" in capsys.readouterr().err


def test_folder_mode_writes_reports_and_summary(tmp_path, fixtures, lnk_fx, mail_fx):
    folder = tmp_path / "reported"
    (folder / "sub").mkdir(parents=True)
    (folder / "notes.txt").write_bytes(b"meeting at three")
    (folder / "sub" / "Invoice.pdf.lnk").write_bytes(lnk_fx.encoded_powershell())
    (folder / "phish.eml").write_bytes(mail_fx.phish_eml())
    out = tmp_path / "out"
    assert cli.main(["triage", str(folder), "--out", str(out), "--format", "all"]) == 0
    summary = (out / "summary.md").read_text()
    rows = [line for line in summary.splitlines() if line.startswith("| `")]
    assert len(rows) == 3
    assert "MALICIOUS" in rows[0] and "MALICIOUS" in rows[1]  # worst first
    assert "notes.txt" in rows[2]
    assert "https://" not in summary
    page = (out / "summary.html").read_text()
    assert "<script" not in page and "default-src 'none'" in page
    assert len(list(out.glob("*.html"))) == 4  # three reports and the summary


def test_html_format(make_file, mail_fx, tmp_path):
    path = make_file("phish.eml", mail_fx.phish_eml())
    out = tmp_path / "out"
    assert cli.main(["triage", str(path), "--out", str(out), "--format", "html"]) == 0
    (page,) = list(out.glob("*.html"))
    text = page.read_text()
    assert 'class="banner mal"' in text


def test_oversized_file_rejected(make_file, capsys):
    path = make_file("big.bin", b"x" * 2048)
    assert cli.main(["triage", str(path), "--max-size", "1K"]) == cli.EXIT_INPUT
    assert "larger than --max-size" in capsys.readouterr().err


def test_bad_allowlist_is_usage_error(make_file, tmp_path, capsys):
    path = make_file("a.txt", b"hello world text\n")
    bad = tmp_path / "bad.toml"
    bad.write_text("[nope]\n", encoding="utf-8")
    assert cli.main(["triage", str(path), "--allowlist", str(bad)]) == cli.EXIT_USAGE
    assert "unknown section" in capsys.readouterr().err


def test_custom_allowlist_applies(make_file, fixtures, tmp_path, capsys):
    path = make_file("a.exe", fixtures.strings_exe())
    al = tmp_path / "al.toml"
    al.write_text('[domains]\nsuffix = ["example.com"]\n', encoding="utf-8")
    assert cli.main(["triage", str(path), "--format", "json", "--allowlist", str(al)]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert not any("example.com" in i["raw"] for i in doc["indicators"])
    assert doc["allowlisted_counts"]["domain"] >= 1


@pytest.mark.parametrize(("text", "value"), [("1024", 1024), ("50MB", 50 * 1024**2),
                                             ("1g", 1024**3)])
def test_parse_size(text, value):
    assert cli.parse_size(text) == value


def test_usage_errors_exit_2(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["triage"])
    assert exc.value.code == 2


RULES = __import__("pathlib").Path(__file__).parent / "rules"


def test_yara_and_capa_options(make_file, fixtures, capsys):
    path = make_file("s.exe", fixtures.suspicious_exe())
    argv = ["triage", str(path), "--format", "json", "--yara-rules", str(RULES / "yara"),
            "--capa-rules", str(RULES / "capa"), "--capa-timeout", "120"]
    assert cli.main(argv) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["analyzers"]["yara"]["status"] == "ok"
    assert doc["analyzers"]["yara"]["data"]["matches"][0]["rule"] == "Fixture_Payload_URL"
    if doc["analyzers"]["capa"]["status"] != "unavailable":
        assert doc["analyzers"]["capa"]["data"]["capabilities"]


def test_rules_from_environment(make_file, fixtures, capsys, monkeypatch):
    monkeypatch.setenv("UNOPENED_YARA_RULES", str(RULES / "yara"))
    path = make_file("eicar.com", fixtures.EICAR)
    assert cli.main(["triage", str(path), "--format", "json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert [m["rule"] for m in doc["analyzers"]["yara"]["data"]["matches"]] == ["EICAR_Test_File"]


def test_unconfigured_rules_are_loud(make_file, fixtures, capsys, monkeypatch):
    monkeypatch.delenv("UNOPENED_YARA_RULES", raising=False)
    monkeypatch.delenv("UNOPENED_CAPA_RULES", raising=False)
    path = make_file("a.exe", fixtures.benign_exe())
    assert cli.main(["triage", str(path)]) == 0
    md = capsys.readouterr().out
    assert "## Warning: some checks did not complete" in md
    assert "no YARA rules configured" in md
    # Without the capa package the missing library is reported first; either way the
    # capa gap must be loud, never silent.
    if importlib.util.find_spec("capa") is not None:
        assert "no capa rules configured" in md
    else:
        assert "**capa**: UNAVAILABLE. Python package 'capa' is not installed" in md


def test_archive_options(make_file, arch_fx, capsys):
    data = arch_fx.zip_crypto({"a.txt": b"secret text"}, password="pw1")
    path = make_file("a.zip", data)
    argv = ["triage", str(path), "--format", "json", "--archive-password", "pw1",
            "--max-depth", "2", "--max-files", "5", "--max-total-size", "1MB",
            "--max-ratio", "50"]
    assert cli.main(argv) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["analyzers"]["archive"]["data"]["password_used"] == "pw1"
    assert doc["members"][0]["report"]["identification"]["kind"] == "text"
    assert doc["members"][0]["member"]["raw"]["name"] == "a.txt"


def test_markdown_has_verdict_and_members(make_file, arch_fx, lnk_fx, capsys):
    path = make_file("a.zip", arch_fx.zip_plain({"run.lnk": lnk_fx.encoded_powershell()}))
    assert cli.main(["triage", str(path)]) == 0
    md = capsys.readouterr().out
    assert "| Verdict | **MALICIOUS**" in md
    assert "## Members" in md and "### Member: `run.lnk`" in md
    assert "V-MAL-09" in md and "V-MAL-03" in md


def test_reputation_flag_without_keys_is_loud_and_offline(make_file, fixtures, capsys,
                                                         monkeypatch):
    monkeypatch.delenv("ABUSECH_API_KEY", raising=False)
    monkeypatch.delenv("VT_API_KEY", raising=False)
    path = make_file("a.exe", fixtures.benign_exe())
    assert cli.main(["triage", str(path), "--reputation", "--format", "json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    sources = doc["reputation"]["sources"]
    assert {s["status"] for s in sources.values()} == {"skipped"}
    assert doc["verdict"]["confidence"] == "low"
