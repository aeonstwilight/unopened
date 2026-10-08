"""Bounded extraction of archive members, disk-image files and PDF attachments (rule 4).

Members are written to a private temporary directory under index-based names
(0001.bin, ...), so hostile names such as ../../evil.exe can never choose where a
file lands. Original names are kept as metadata and checked for traversal tricks.
Files are created 0600 and never made executable. The pipeline deletes the whole
directory when triage finishes, including after errors.

Limits are checked against declared sizes first and again while bytes are written,
because archive headers can lie:
- per-member size, total extracted size and member count (shared across recursion)
- compression ratio (uncompressed / compressed), ignored for small members
- nesting depth (enforced by the pipeline: archives at the maximum depth are listed,
  not extracted)
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

RATIO_FLOOR = 1024 * 1024
CHUNK = 1 << 16


@dataclass(frozen=True)
class Limits:
    max_depth: int = 3
    max_files: int = 1000
    max_total_size: int = 500 * 1024 * 1024
    max_member_size: int = 200 * 1024 * 1024
    max_ratio: float = 100.0


@dataclass
class Budget:
    """What is left for the whole triage, across all nesting levels."""

    files_left: int
    bytes_left: int

    @classmethod
    def from_limits(cls, limits: Limits) -> Budget:
        return cls(limits.max_files, limits.max_total_size)


class LimitHit(Exception):
    """Extraction stopped at a safety limit. `fatal` means no further members may be
    extracted (budget exhausted); otherwise only this member is skipped."""

    def __init__(self, message: str, fatal: bool = False):
        super().__init__(message)
        self.fatal = fatal


def name_flags(name: str) -> list[str]:
    flags = []
    parts = re.split(r"[\\/]", name)
    if ".." in parts:
        flags.append("path_traversal")
    if name.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", name):
        flags.append("absolute_path")
    if any(c in name for c in "‮‭‪‫⁦⁧⁨"):
        flags.append("direction_override")
    if "\x00" in name:
        flags.append("nul_in_name")
    return flags


def basename(name: str) -> str:
    return re.split(r"[\\/]", name.rstrip("/\\"))[-1] or name


@dataclass
class MemberWriter:
    """Writes members into `directory` within `limits` and the shared budget numbers
    given at construction. Records what it did in `members` for the report."""

    directory: Path | None
    limits: Limits
    files_left: int
    bytes_left: int
    members: list[dict[str, Any]] = field(default_factory=list)
    stopped: str | None = None
    used_files: int = 0
    used_bytes: int = 0

    @property
    def can_extract(self) -> bool:
        return self.directory is not None and self.stopped is None

    def record(self, name: str, size: int | None, *, skipped: str | None = None,
               compressed: int | None = None, **extra: Any) -> dict[str, Any]:
        entry = {
            "name": name, "size": size, "compressed_size": compressed, "stored": None,
            "skipped": skipped, "flags": name_flags(name), **extra,
        }
        self.members.append(entry)
        return entry

    def check_declared(self, size: int | None, compressed: int | None) -> str | None:
        """Reason to skip before reading anything, or None."""
        if self.directory is None:
            return "not extracted: nesting depth limit reached"
        if self.stopped:
            return f"not extracted: {self.stopped}"
        if self.files_left - self.used_files <= 0:
            self.stopped = f"member count limit ({self.limits.max_files}) reached"
            return f"not extracted: {self.stopped}"
        if size is not None:
            if size > self.limits.max_member_size:
                return (f"not extracted: declares {size:,} bytes, over the per-member limit "
                        f"({self.limits.max_member_size:,})")
            if size > self.bytes_left - self.used_bytes:
                self.stopped = f"total size limit ({self.limits.max_total_size:,} bytes) reached"
                return f"not extracted: {self.stopped}"
            if compressed and size > RATIO_FLOOR and size / compressed > self.limits.max_ratio:
                return (f"not extracted: compression ratio {size / compressed:,.0f}:1 exceeds "
                        f"{self.limits.max_ratio:,.0f}:1 (possible zip bomb)")
        return None

    def open(self, name: str, size: int | None, compressed: int | None = None,
             **extra: Any) -> _Sink | None:
        """Start writing one member, or record why it is skipped and return None."""
        reason = self.check_declared(size, compressed)
        if reason:
            self.record(name, size, skipped=reason, compressed=compressed, **extra)
            return None
        entry = self.record(name, size, compressed=compressed, **extra)
        index = len(self.members)
        stored = f"{index:04d}.bin"
        assert self.directory is not None
        fd = os.open(self.directory / stored, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        return _Sink(self, entry, stored, os.fdopen(fd, "wb"), compressed)

    def write_all(self, name: str, chunks: Iterable[bytes], size: int | None,
                  compressed: int | None = None, **extra: Any) -> dict[str, Any] | None:
        sink = self.open(name, size, compressed, **extra)
        if sink is None:
            return None
        with sink:
            for chunk in chunks:
                sink.write(chunk)
        return sink.entry


class _Sink:
    """File-like writer enforcing the limits while bytes arrive. Raising LimitHit
    inside write() aborts the decompressor that feeds it."""

    def __init__(self, writer: MemberWriter, entry: dict[str, Any], stored: str, fh: Any,
                 compressed: int | None):
        self.writer, self.entry, self.stored, self.fh = writer, entry, stored, fh
        self.compressed = compressed
        self.written = 0
        self.failed: str | None = None

    def write(self, data: bytes) -> int:
        w = self.writer
        self.written += len(data)
        if self.written > w.limits.max_member_size:
            raise LimitHit(f"inflates past the per-member limit ({w.limits.max_member_size:,})")
        if w.used_bytes + self.written > w.bytes_left:
            w.stopped = f"total size limit ({w.limits.max_total_size:,} bytes) reached"
            raise LimitHit(w.stopped, fatal=True)
        if (self.compressed and self.written > RATIO_FLOOR
                and self.written / self.compressed > w.limits.max_ratio):
            raise LimitHit(f"compression ratio exceeds {w.limits.max_ratio:,.0f}:1 while "
                           "inflating (possible zip bomb)")
        self.fh.write(data)
        return len(data)

    def __enter__(self) -> _Sink:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        self.fh.close()
        path = self.writer.directory / self.stored  # type: ignore[operator]
        if exc is None and self.failed is None:
            self.entry["stored"] = self.stored
            self.entry["size"] = self.written
            self.writer.used_files += 1
            self.writer.used_bytes += self.written
            return False
        path.unlink(missing_ok=True)
        reason = self.failed or (str(exc) if exc else "failed")
        self.entry["skipped"] = f"not extracted: {reason}"
        if isinstance(exc, LimitHit):
            return True  # handled: the member is recorded as skipped
        return False

    def fail(self, reason: str) -> None:
        self.failed = reason

    def reset(self) -> None:
        """Discard what was written so far (e.g. before retrying with another password)."""
        self.fh.seek(0)
        self.fh.truncate()
        self.written = 0
