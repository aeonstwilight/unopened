from __future__ import annotations

import os
import tempfile

import pytest

from unopened import pipeline
from unopened.analyzers import Options
from unopened.extraction import Limits
from unopened.model import Severity, Status


def triage(path, **kw):
    limits = kw.pop("limits", Limits())
    return pipeline.triage(path, Options(limits=limits, **kw))


def archive(report):
    return report.result("archive")


def ids(report):
    return {f.id: f.severity for f in report.findings()}


def test_zipcrypto_with_infected(make_file, arch_fx, fixtures):
    data = arch_fx.zip_crypto({"invoice.pdf.exe": fixtures.benign_exe(), "readme.txt": b"hi"})
    r = triage(make_file("mail.zip", data))
    a = archive(r)
    assert a.status == Status.OK and a.data["password_used"] == "infected"
    assert [c["member"]["name"] for c in r.children] == ["invoice.pdf.exe", "readme.txt"]
    pe = r.children[0]["report"]
    assert pe.file_type.kind == "pe"
    assert any(m.id == "identify.double_extension" for m in pe.file_type.mismatches)
    assert ids(r)["container.deceptive_member"] == Severity.HIGH
    assert ids(r)["archive.password_protected"] == Severity.LOW


def test_aes_zip(make_file, arch_fx, lnk_fx):
    pytest.importorskip("pyzipper")
    r = triage(make_file("a.zip", arch_fx.zip_aes({"run.lnk": lnk_fx.encoded_powershell()})))
    assert archive(r).data["password_used"] == "infected"
    assert r.children[0]["report"].verdict["value"] == "malicious"
    assert r.verdict["value"] == "malicious" and r.verdict["rule"] == "V-MAL-09"


def test_extra_password(make_file, arch_fx):
    data = arch_fx.zip_crypto({"a.txt": b"secret text"}, password="s3cret")
    r = triage(make_file("a.zip", data), archive_passwords=("infected", "s3cret"))
    assert archive(r).data["password_used"] == "s3cret"
    assert r.children[0]["report"].file_type.kind == "text"


def test_unknown_password_is_could_not_analyze(make_file, arch_fx):
    r = triage(make_file("a.zip", arch_fx.zip_crypto({"a.txt": b"x"}, password="other")))
    (m,) = archive(r).data["members"]
    assert m["password_unknown"] and m["stored"] is None
    assert r.verdict["value"] == "could not analyze"
    assert "archive.password_unknown" in ids(r)


def test_nesting_depth_limit(make_file, arch_fx, fixtures):
    r = triage(make_file("n.zip", arch_fx.nested_zip(5, {"deep.exe": fixtures.benign_exe()})))
    chain = []
    node = r
    while node.children:
        node = node.children[0]["report"]
        chain.append(node.depth)
    assert chain == [1, 2, 3]  # level3.zip is at depth 3 and is not extracted
    assert archive(node).data["depth_limited"] is True
    assert "archive.depth_limit" in ids(node)
    assert r.verdict["value"] == "could not analyze"


def test_path_traversal_names_are_neutralized(make_file, arch_fx):
    r = triage(make_file("t.zip", arch_fx.zip_plain({"../../evil.txt": b"x", "/abs.txt": b"y"})))
    members = archive(r).data["members"]
    assert members[0]["flags"] == ["path_traversal"]
    assert members[1]["flags"] == ["absolute_path"]
    assert {m["stored"] for m in members} == {"0001.bin", "0002.bin"}
    assert ids(r)["archive.path_traversal"] == Severity.HIGH


def test_ratio_limit_stops_zip_bomb(make_file, arch_fx):
    r = triage(make_file("bomb.zip", arch_fx.zip_bomb(16 * 1024 * 1024)))
    (m,) = archive(r).data["members"]
    assert m["stored"] is None and "zip bomb" in m["skipped"]
    assert "archive.bomb" in ids(r)
    assert r.verdict["value"] == "could not analyze"


def test_total_size_limit(make_file, arch_fx):
    members = {f"f{i}.txt": os.urandom(64 * 1024) for i in range(10)}
    limits = Limits(max_total_size=256 * 1024)
    r = triage(make_file("big.zip", arch_fx.zip_plain(members)), limits=limits)
    a = archive(r)
    assert a.data["stopped"].startswith("total size limit")
    assert 0 < a.data["extracted_files"] < 10
    assert "archive.limit_hit" in ids(r)
    assert any("not extracted" in n.reason for n in r.not_checked)


def test_file_count_limit_is_shared_across_nesting(make_file, arch_fx):
    inner = arch_fx.zip_plain({f"i{i}.txt": b"x" for i in range(10)})
    outer = arch_fx.zip_plain({"a.zip": inner, "b.zip": inner})
    r = triage(make_file("o.zip", outer), limits=Limits(max_files=12))
    total = sum(1 for rep in pipeline.walk(r) for _ in [rep]) - 1
    assert total == 12  # 2 inner zips + 10 members, then the budget is spent


def test_declared_size_over_member_limit(make_file, arch_fx):
    r = triage(make_file("z.zip", arch_fx.zip_plain({"big.bin": os.urandom(300 * 1024)})),
               limits=Limits(max_member_size=100 * 1024))
    (m,) = archive(r).data["members"]
    assert "per-member limit" in m["skipped"]


def test_7z_with_password(make_file, arch_fx):
    pytest.importorskip("py7zr")
    data = arch_fx.seven_zip({"doc/script.ps1": arch_fx.PS_DOWNLOADER}, password="infected")
    r = triage(make_file("p.7z", data))
    assert archive(r).data["password_used"] == "infected"
    (child,) = r.children
    assert child["report"].verdict["rule"] == "V-MAL-07"
    assert "archive.motw" in ids(r)


def test_7z_encrypted_headers(make_file, arch_fx):
    pytest.importorskip("py7zr")
    data = arch_fx.seven_zip({"a.txt": b"hello"}, password="infected", header_encryption=True)
    r = triage(make_file("h.7z", data))
    assert [c["member"]["name"] for c in r.children] == ["a.txt"]


def test_7z_wrong_password(make_file, arch_fx):
    pytest.importorskip("py7zr")
    r = triage(make_file("w.7z", arch_fx.seven_zip({"a.txt": b"hello there"}, password="zzz")))
    assert r.verdict["value"] == "could not analyze"
    assert not r.children


def test_iso_lure_with_hidden_payload(make_file, arch_fx, lnk_fx, fixtures):
    pytest.importorskip("pycdlib")
    data = arch_fx.iso_image({"Invoice.lnk": lnk_fx.encoded_powershell(),
                              "payload.dll": fixtures.benign_dll()}, hidden={"payload.dll"})
    r = triage(make_file("lure.iso", data))
    members = {m["name"]: m for m in archive(r).data["members"]}
    assert members["payload.dll"]["hidden"] is True
    assert members["Invoice.lnk"]["hidden"] is False
    found = ids(r)
    assert found["container.lnk_with_hidden_files"] == Severity.HIGH
    assert found["archive.hidden_files"] == Severity.MEDIUM
    assert r.verdict["value"] == "malicious"


def test_temp_dir_is_removed_even_on_failure(make_file, arch_fx, monkeypatch):
    before = set(os.listdir(tempfile.gettempdir()))

    def boom(*a, **k):
        raise RuntimeError("verdict exploded")

    monkeypatch.setattr(pipeline, "evaluate", boom)
    with pytest.raises(RuntimeError):
        triage(make_file("a.zip", arch_fx.zip_plain({"a.txt": b"x"})))
    leftover = {n for n in set(os.listdir(tempfile.gettempdir())) - before
                if n.startswith("unopened-")}
    assert leftover == set()


def test_extracted_files_are_private_and_not_executable(make_file, arch_fx, monkeypatch):
    seen = []
    real = pipeline._triage

    def spy(session, path, **kw):
        if kw.get("depth"):
            st = path.stat()
            seen.append((oct(st.st_mode & 0o777), oct(path.parent.stat().st_mode & 0o777)))
        return real(session, path, **kw)

    monkeypatch.setattr(pipeline, "_triage", spy)
    triage(make_file("a.zip", arch_fx.zip_plain({"run.exe": b"MZ not really"})))
    assert seen == [("0o600", "0o700")]


def test_damaged_zip_member_is_reported(make_file, arch_fx):
    data = bytearray(arch_fx.zip_plain({"a.txt": b"hello world " * 100}))
    data[40:60] = b"\xff" * 20  # corrupt the compressed bytes
    r = triage(make_file("d.zip", bytes(data)))
    a = archive(r)
    assert a.status == Status.PARTIAL or a.status == Status.ERROR
