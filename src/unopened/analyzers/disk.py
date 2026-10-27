"""Virtual hard disks (VHD, VHDX): the footer or header is parsed, the files inside are
not extracted in this version (that needs an NTFS reader). The report says so, and the
verdict is "could not analyze" so that a disk image never looks clean."""

from __future__ import annotations

import struct
from datetime import UTC, datetime, timedelta

from ..model import AnalyzerOutput, Finding, Severity
from . import Context

VHD_EPOCH = datetime(2000, 1, 1, tzinfo=UTC)
DISK_TYPES = {2: "fixed", 3: "dynamic", 4: "differencing"}


def analyze_vhd(ctx: Context) -> AnalyzerOutput:
    out = AnalyzerOutput()
    size = ctx.size
    with ctx.path.open("rb") as f:
        head = f.read(65536)
        if size >= 512:
            f.seek(size - 512)
            tail = f.read(512)
        else:
            tail = b""
    sub = ctx.file_type.subtype
    if sub == "vhdx":
        creator = head[8:520].decode("utf-16-le", "replace").split("\0", 1)[0]
        out.data = {"format": "VHDX", "creator": creator.strip()}
    else:
        footer = tail if tail.startswith(b"conectix") else head[:512]
        disk_type = struct.unpack(">I", footer[60:64])[0] if len(footer) >= 64 else 0
        stamp = struct.unpack(">I", footer[24:28])[0] if len(footer) >= 28 else 0
        current = struct.unpack(">Q", footer[48:56])[0] if len(footer) >= 56 else 0
        out.data = {
            "format": "VHD",
            "disk_type": DISK_TYPES.get(disk_type, f"unknown ({disk_type})"),
            "creator": footer[28:32].decode("latin-1", "replace").strip("\0 "),
            "created": (VHD_EPOCH + timedelta(seconds=stamp)).isoformat() if stamp else None,
            "virtual_size": current,
        }
        if disk_type == 2:
            mbr = head[:512]
            if len(mbr) == 512 and mbr[510:512] == b"\x55\xaa":
                out.data["partition_types"] = [f"0x{mbr[446 + 16 * i + 4]:02x}"
                                               for i in range(4) if mbr[446 + 16 * i + 4]]
    out.findings.append(Finding(
        "vhd.disk_image", Severity.MEDIUM, f"Virtual hard disk ({out.data['format']})",
        "Windows mounts it as a drive on double-click, and Windows versions without the "
        "November 2022 updates do not pass Mark-of-the-Web to the files inside. Delivering "
        "programs in disk images is a common way past mail filters.",
    ))
    out.not_checked.append(
        "Files inside the virtual disk: not extracted in this version. Mount it read-only "
        "inside the analysis VM and triage its files. Strings and YARA above did scan the "
        "raw disk bytes, which include uncompressed file contents.")
    return out
