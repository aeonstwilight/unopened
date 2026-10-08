from __future__ import annotations

import io
import zipfile

import pytest

from unopened.safezip import LimitExceeded, MemberLimits, read_member


def make_zip(name, data, compression=zipfile.ZIP_DEFLATED):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as zf:
        zf.writestr(name, data)
    return zipfile.ZipFile(io.BytesIO(buf.getvalue()))


def test_reads_normal_member():
    zf = make_zip("a.txt", b"hello" * 100)
    assert read_member(zf, zf.getinfo("a.txt"), MemberLimits()) == b"hello" * 100


def test_declared_size_over_limit():
    zf = make_zip("big.bin", bytes(2 * 1024 * 1024))
    with pytest.raises(LimitExceeded, match="over the"):
        read_member(zf, zf.getinfo("big.bin"), MemberLimits(max_size=1024 * 1024))


def test_ratio_limit():
    zf = make_zip("zeros.bin", bytes(4 * 1024 * 1024))
    with pytest.raises(LimitExceeded, match="compression ratio"):
        read_member(zf, zf.getinfo("zeros.bin"), MemberLimits())


def test_lying_header_is_caught_while_inflating():
    zf = make_zip("liar.bin", bytes(3 * 1024 * 1024))
    info = zf.getinfo("liar.bin")
    info.file_size = 10  # forge the declared size
    # Either our running size check or zipfile's own CRC/size check stops it; both are
    # handled by callers, and neither returns the oversized data.
    with pytest.raises((LimitExceeded, zipfile.BadZipFile)):
        read_member(zf, info, MemberLimits(max_size=1024 * 1024, max_ratio=10_000))


def test_small_compressible_member_is_fine():
    zf = make_zip("small.xml", b"<a/>" * 1000)
    assert len(read_member(zf, zf.getinfo("small.xml"), MemberLimits())) == 4000


def test_encrypted_member_refused():
    zf = make_zip("a.txt", b"x")
    info = zf.getinfo("a.txt")
    info.flag_bits |= 0x1
    with pytest.raises(LimitExceeded, match="encrypted"):
        read_member(zf, info, MemberLimits())
