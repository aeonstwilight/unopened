from __future__ import annotations

import pytest

from unopened.extraction import LimitHit, Limits, MemberWriter, name_flags


def writer(tmp_path, **limits):
    lim = Limits(**limits)
    return MemberWriter(tmp_path, lim, lim.max_files, lim.max_total_size)


def test_writes_index_named_private_files(tmp_path):
    w = writer(tmp_path)
    entry = w.write_all("../../etc/passwd", [b"abc", b"def"], 6)
    assert entry["stored"] == "0001.bin" and entry["size"] == 6
    assert (tmp_path / "0001.bin").read_bytes() == b"abcdef"
    assert oct((tmp_path / "0001.bin").stat().st_mode & 0o777) == "0o600"
    assert entry["flags"] == ["path_traversal"]


def test_actual_size_enforced_when_declared_size_lies(tmp_path):
    w = writer(tmp_path, max_member_size=10)
    entry = w.write_all("liar", [b"x" * 8, b"x" * 8], 5)
    assert entry["stored"] is None and "per-member limit" in entry["skipped"]
    assert list(tmp_path.iterdir()) == []


def test_total_budget_is_fatal(tmp_path):
    w = writer(tmp_path, max_total_size=10)
    w.write_all("a", [b"x" * 6], 6)
    second = w.write_all("b", [b"x" * 6], None)
    assert second["stored"] is None
    assert w.stopped and w.check_declared(1, 1).startswith("not extracted: total size")


def test_ratio_checked_while_inflating(tmp_path):
    w = writer(tmp_path, max_ratio=10)
    entry = w.write_all("bomb", (bytes(1 << 20) for _ in range(3)), None, compressed=1000)
    assert "ratio" in entry["skipped"]


def test_no_directory_means_no_extraction(tmp_path):
    w = MemberWriter(None, Limits(), 10, 10)
    assert w.open("a", 1) is None
    assert "depth" in w.members[0]["skipped"]


def test_limit_hit_is_an_exception_type():
    assert issubclass(LimitHit, Exception)


@pytest.mark.parametrize(("name", "flags"), [
    ("ok/file.txt", []),
    ("..\\..\\x.exe", ["path_traversal"]),
    ("C:\\Windows\\x.exe", ["absolute_path"]),
    ("invoice\u202efdp.exe", ["direction_override"]),
])
def test_name_flags(name, flags):
    assert name_flags(name) == flags
