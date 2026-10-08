"""Cryptographic and fuzzy hashes. Reads the file as bytes in chunks; nothing else."""

from __future__ import annotations

import hashlib
from pathlib import Path

CHUNK = 1 << 20
TLSH_MIN_BYTES = 50


def crypto_hashes(path: Path) -> dict[str, str]:
    md5, sha1, sha256 = hashlib.md5(usedforsecurity=False), hashlib.sha1(
        usedforsecurity=False
    ), hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(CHUNK):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def tlsh_hash(path: Path) -> str | None:
    """Return the TLSH digest, or None if the data has too little variety to hash.

    Raises ImportError when py-tlsh is not installed; the runner reports that as
    'unavailable'."""
    import tlsh

    h = tlsh.Tlsh()
    with path.open("rb") as f:
        while chunk := f.read(CHUNK):
            h.update(chunk)
    h.final()
    digest = h.hexdigest()
    if not digest or digest == "TNULL":
        return None
    return digest
