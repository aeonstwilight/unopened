"""Bounded reads of individual ZIP members (rule 4).

Declared sizes in a ZIP can lie, so limits are checked against the declared header
values first and then enforced again while decompressing.
"""

from __future__ import annotations

import zipfile
from dataclasses import dataclass

CHUNK = 1 << 16


class LimitExceeded(Exception):
    """A member was not read because it would break a safety limit."""


@dataclass(frozen=True)
class MemberLimits:
    max_size: int = 50 * 1024 * 1024  # uncompressed bytes per member
    max_ratio: float = 200.0  # uncompressed / compressed
    ratio_floor: int = 1024 * 1024  # small members are exempt from the ratio check


def read_member(zf: zipfile.ZipFile, info: zipfile.ZipInfo, limits: MemberLimits) -> bytes:
    name = info.filename
    if info.flag_bits & 0x1:
        raise LimitExceeded(f"{name}: member is encrypted; not read")
    if info.file_size > limits.max_size:
        raise LimitExceeded(
            f"{name}: declares {info.file_size:,} bytes, over the {limits.max_size:,}-byte limit"
        )
    _check_ratio(name, info.file_size, info.compress_size, limits)
    out = bytearray()
    with zf.open(info) as f:
        while chunk := f.read(CHUNK):
            out += chunk
            if len(out) > limits.max_size:
                raise LimitExceeded(
                    f"{name}: inflates past the {limits.max_size:,}-byte limit "
                    "(declared size was false)"
                )
            _check_ratio(name, len(out), info.compress_size, limits)
    return bytes(out)


def _check_ratio(name: str, size: int, compressed: int, limits: MemberLimits) -> None:
    if size <= limits.ratio_floor:
        return
    ratio = size / max(compressed, 1)
    if ratio > limits.max_ratio:
        raise LimitExceeded(
            f"{name}: compression ratio {ratio:,.0f}:1 exceeds {limits.max_ratio:,.0f}:1 "
            "(possible zip bomb)"
        )
