from __future__ import annotations

import hashlib

import pytest

from unopened import hashing, runner
from unopened.analyzers import Context, Options, registry
from unopened.model import FileType, Status


def test_known_digests(make_file):
    path = make_file("abc", b"abc")
    assert hashing.crypto_hashes(path) == {
        "md5": "900150983cd24fb0d6963f7d28e17f72",
        "sha1": "a9993e364706816aba3e25717850c26c9cd0d89d",
        "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    }


def test_chunked_matches_hashlib(make_file, fixtures):
    data = fixtures.pseudo_random(3 * hashing.CHUNK + 17)
    digest = hashing.crypto_hashes(make_file("big", data))["sha256"]
    assert digest == hashlib.sha256(data).hexdigest()


def _ctx(path):
    return Context(path, FileType("unknown", "x"), Options(), path.stat().st_size)


def _tlsh():
    return next(a for a in registry() if a.name == "tlsh")


def test_tlsh_present(make_file, fixtures):
    pytest.importorskip("tlsh")
    path = make_file("r", fixtures.pseudo_random(4096))
    result = runner.run_analyzer(_tlsh(), _ctx(path), isolate=False)
    assert result.status == Status.OK
    assert result.data["tlsh"].startswith("T1")


def test_tlsh_too_small(make_file):
    pytest.importorskip("tlsh")
    path = make_file("tiny", b"0123456789")
    result = runner.run_analyzer(_tlsh(), _ctx(path), isolate=False)
    assert result.status == Status.OK and result.data["tlsh"] is None
    assert "at least 50 bytes" in result.not_checked[0]


def test_tlsh_missing_is_unavailable(make_file, monkeypatch):
    monkeypatch.setattr(
        runner, "_missing_module", lambda names: "tlsh" if "tlsh" in names else None
    )
    path = make_file("r", b"x" * 100)
    result = runner.run_analyzer(_tlsh(), _ctx(path), isolate=False)
    assert result.status == Status.UNAVAILABLE
    assert "unopened[fuzzy]" in result.message
