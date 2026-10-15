"""Synthetic, benign test fixtures built byte by byte.

The PE builder writes a minimal but well-formed PE32/PE32+ image. Its only code is a
single `ret` instruction; imports are just names in a table. Nothing here is, or is
derived from, real malware. Fixtures are generated at test time into a temp directory,
so no binaries are committed.

Documentation-only network values are used throughout: example.com/.org/.net
(RFC 2606) and 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (RFC 5737).

Usage outside pytest:  python tests/fixtures/build.py OUTPUT_DIR
"""

from __future__ import annotations

import hashlib
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

FILE_ALIGN = 0x200
SECT_ALIGN = 0x1000
IMAGE_BASE = 0x400000

SCN_CODE = 0x00000020
SCN_IDATA = 0x00000040
SCN_EXEC = 0x20000000
SCN_READ = 0x40000000
SCN_WRITE = 0x80000000

TEXT = SCN_CODE | SCN_EXEC | SCN_READ
RDATA = SCN_IDATA | SCN_READ
DATA = SCN_IDATA | SCN_READ | SCN_WRITE

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def align(value: int, to: int) -> int:
    return (value + to - 1) // to * to


def pseudo_random(n: int, seed: bytes = b"unopened") -> bytes:
    """Deterministic high-entropy bytes."""
    out = bytearray()
    block = seed
    while len(out) < n:
        block = hashlib.sha256(block).digest()
        out += block
    return bytes(out[:n])


@dataclass
class Section:
    name: bytes
    data: bytes
    characteristics: int
    virtual_size: int | None = None  # defaults to len(data)
    raw: bool = True  # False: no bytes on disk (SizeOfRawData = 0)


@dataclass
class PESpec:
    imports: dict[str, list[str]] = field(
        default_factory=lambda: {
            "kernel32.dll": ["ExitProcess", "GetModuleHandleA", "GetCommandLineA",
                             "GetStdHandle", "WriteFile", "HeapAlloc", "HeapFree"],
        }
    )
    exports: list[str] = field(default_factory=list)
    dll: bool = False
    pe32plus: bool = False
    subsystem: int = 3  # console
    timestamp: int = 1_700_000_000  # 2023-11-14
    rdata_extra: bytes = b""  # planted strings
    extra_sections: list[Section] = field(default_factory=list)
    text_characteristics: int = TEXT
    entry_point: int | None = None  # RVA override
    overlay: bytes = b""
    certificate: bytes | None = None  # raw bCertificate contents of a WIN_CERTIFICATE
    pdb_path: str | None = None
    reproducible: bool = False  # add an IMAGE_DEBUG_TYPE_REPRO entry (needs pdb_path)


def _build_rdata(spec: PESpec, rva: int, ptr_size: int) -> tuple[bytes, dict[str, tuple[int, int]]]:
    """Import table, export table, debug directory and planted strings for .rdata."""
    buf = bytearray()
    dirs: dict[str, tuple[int, int]] = {}

    def here() -> int:
        return rva + len(buf)

    def put(data: bytes, alignment: int = 4) -> int:
        while len(buf) % alignment:
            buf.append(0)
        at = here()
        buf.extend(data)
        return at

    # Imports: descriptors first, with ILT/IAT/name RVAs patched in once known.
    if spec.imports:
        desc_size = 20 * (len(spec.imports) + 1)
        desc_at = put(b"\0" * desc_size)
        thunk_fmt = "<Q" if ptr_size == 8 else "<I"
        for i, (dll, funcs) in enumerate(spec.imports.items()):
            hint_rvas = [put(struct.pack("<H", 0) + f.encode() + b"\0", 2) for f in funcs]
            thunks = b"".join(struct.pack(thunk_fmt, r) for r in hint_rvas) + b"\0" * ptr_size
            ilt = put(thunks, ptr_size)
            iat = put(thunks, ptr_size)
            name = put(dll.encode() + b"\0", 2)
            off = desc_at - rva + 20 * i
            buf[off : off + 20] = struct.pack("<IIIII", ilt, 0, 0, name, iat)
        dirs["import"] = (desc_at, desc_size)

    if spec.exports:
        names = sorted(spec.exports)
        n = len(names)
        dll_name = put(b"fixture.dll\0", 2)
        name_rvas = [put(nm.encode() + b"\0", 1) for nm in names]
        eat = put(b"".join(struct.pack("<I", 0x1000) for _ in names))
        enpt = put(b"".join(struct.pack("<I", r) for r in name_rvas))
        eot = put(b"".join(struct.pack("<H", i) for i in range(n)), 2)
        exp_at = put(struct.pack("<IIHHIIIIIII", 0, spec.timestamp, 0, 0, dll_name, 1, n, n,
                                 eat, enpt, eot))
        dirs["export"] = (exp_at, 40)

    if spec.pdb_path:
        cv = b"RSDS" + bytes(16) + struct.pack("<I", 1) + spec.pdb_path.encode() + b"\0"
        cv_at = put(cv)
        dbg = struct.pack("<IIHHIIII", 0, spec.timestamp, 0, 0, 2, len(cv), cv_at, 0)
        if spec.reproducible:
            dbg += struct.pack("<IIHHIIII", 0, spec.timestamp, 0, 0, 16, 0, 0, 0)
        dbg_at = put(dbg)
        dirs["debug"] = (dbg_at, len(dbg))
        dirs["_cv_rva"] = (cv_at, len(cv))

    if spec.rdata_extra:
        put(spec.rdata_extra, 1)
    return bytes(buf) or b"\0", dirs


def build_pe(spec: PESpec | None = None) -> bytes:
    spec = spec or PESpec()
    ptr_size = 8 if spec.pe32plus else 4
    opt_size = (112 if spec.pe32plus else 96) + 16 * 8
    sections_meta: list[Section] = [
        Section(b".text", b"\xc3" + b"\xcc" * 15, spec.text_characteristics),
    ]
    rdata_rva = SECT_ALIGN * 2
    rdata, dirs = _build_rdata(spec, rdata_rva, ptr_size)
    sections_meta.append(Section(b".rdata", rdata, RDATA))
    sections_meta.extend(spec.extra_sections)

    n = len(sections_meta)
    headers_size = align(0x40 + 4 + 20 + opt_size + 40 * n, FILE_ALIGN)
    va = SECT_ALIGN
    ptr = headers_size
    table, body = bytearray(), bytearray()
    placed = []
    for s in sections_meta:
        vsize = s.virtual_size if s.virtual_size is not None else max(len(s.data), 1)
        raw_size = align(len(s.data), FILE_ALIGN) if s.raw and s.data else 0
        raw_ptr = ptr if raw_size else 0
        placed.append((s, va, vsize, raw_ptr, raw_size))
        table += struct.pack("<8sIIIIIIHHI", s.name.ljust(8, b"\0")[:8], vsize, va, raw_size,
                             raw_ptr, 0, 0, 0, 0, s.characteristics)
        if raw_size:
            body += s.data.ljust(raw_size, b"\0")
            ptr += raw_size
        va += align(vsize, SECT_ALIGN)
    assert placed[1][1] == rdata_rva, "rdata must land at its precomputed RVA"
    size_of_image = va

    data_dirs = [(0, 0)] * 16
    if "export" in dirs:
        data_dirs[0] = dirs["export"]
    if "import" in dirs:
        data_dirs[1] = dirs["import"]
    if "debug" in dirs:
        data_dirs[6] = dirs["debug"]

    tail = bytearray(spec.overlay)
    cert_offset = 0
    if spec.certificate is not None:
        cert_offset = headers_size + len(body) + len(spec.overlay)
        win_cert = struct.pack("<IHH", 8 + len(spec.certificate), 0x0200, 0x0002) + spec.certificate
        win_cert = win_cert.ljust(align(len(win_cert), 8), b"\0")
        data_dirs[4] = (cert_offset, len(win_cert))
        tail += win_cert

    # Debug directory's PointerToRawData must be a file offset.
    if "debug" in dirs:
        cv_rva = dirs["_cv_rva"][0]
        cv_file = placed[1][3] + (cv_rva - rdata_rva)
        dbg_off = placed[1][3] + (dirs["debug"][0] - rdata_rva)
        body_off = dbg_off - headers_size + 24
        body[body_off : body_off + 4] = struct.pack("<I", cv_file)

    machine = 0x8664 if spec.pe32plus else 0x14C
    characteristics = 0x0002 | (0x0020 if spec.pe32plus else 0x0100)
    if spec.dll:
        characteristics |= 0x2000
    coff = struct.pack("<HHIIIHH", machine, n, spec.timestamp, 0, 0, opt_size, characteristics)
    entry = spec.entry_point if spec.entry_point is not None else (0 if spec.dll else SECT_ALIGN)
    if spec.dll and spec.entry_point is None:
        entry = SECT_ALIGN
    size_code = align(len(sections_meta[0].data), FILE_ALIGN)
    if spec.pe32plus:
        opt = struct.pack(
            "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII", 0x20B, 14, 0, size_code, len(rdata), 0, entry,
            SECT_ALIGN, IMAGE_BASE, SECT_ALIGN, FILE_ALIGN, 6, 0, 0, 0, 6, 0, 0, size_of_image,
            headers_size, 0, spec.subsystem, 0x8160, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
        )
    else:
        opt = struct.pack(
            "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII", 0x10B, 14, 0, size_code, len(rdata), 0, entry,
            SECT_ALIGN, rdata_rva, IMAGE_BASE, SECT_ALIGN, FILE_ALIGN, 6, 0, 0, 0, 6, 0, 0,
            size_of_image, headers_size, 0, spec.subsystem, 0x8140, 0x100000, 0x1000, 0x100000,
            0x1000, 0, 16,
        )
    opt += b"".join(struct.pack("<II", a, s) for a, s in data_dirs)
    assert len(opt) == opt_size

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = struct.pack("<I", 0x40)
    header = bytes(dos) + b"PE\0\0" + coff + opt + bytes(table)
    header = header.ljust(headers_size, b"\0")
    return header + bytes(body) + bytes(tail)


# Ready-made fixtures -------------------------------------------------------------------

PLANTED_STRINGS = (
    b"http://malicious.example.com/payload.bin\0"
    b"https://203.0.113.7:8443/gate.php?id=1\0"
    b"contact: admin@example.org\0"
    b"C:\\Users\\Public\\Documents\\update.exe\0"
    b"Software\\Microsoft\\Windows\\CurrentVersion\\Run\0"
    b"HKLM\\SYSTEM\\CurrentControlSet\\Services\\FixtureSvc\0"
    b"\\\\fileserver.example.net\\share\\tools\0"
    b"http://crl.digicert.com/fixture.crl\0"
    b"198.51.100.23\0"
) + "http://utf16.example.net/beacon\0".encode("utf-16-le")


def benign_exe() -> bytes:
    return build_pe(PESpec(pdb_path="C:\\build\\fixture\\Release\\fixture.pdb"))


def benign_dll() -> bytes:
    return build_pe(PESpec(dll=True, exports=["FixtureInit", "FixtureRun"], subsystem=2))


def benign_exe64() -> bytes:
    return build_pe(PESpec(pe32plus=True))


def suspicious_exe() -> bytes:
    """Looks packed and suspicious to a static triage tool, but its code is just `ret`."""
    return build_pe(PESpec(
        imports={
            "kernel32.dll": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                             "IsDebuggerPresent", "LoadLibraryA", "GetProcAddress"],
            "user32.dll": ["SetWindowsHookExW", "GetAsyncKeyState"],
        },
        timestamp=4_000_000_000,  # 2096
        rdata_extra=PLANTED_STRINGS,
        text_characteristics=TEXT | SCN_WRITE,
        extra_sections=[
            Section(b"UPX0", b"", TEXT | SCN_WRITE, virtual_size=0x4000, raw=False),
            Section(b".data", pseudo_random(8192), DATA),
        ],
        overlay=pseudo_random(4096, b"overlay"),
    ))


def strings_exe() -> bytes:
    return build_pe(PESpec(rdata_extra=PLANTED_STRINGS))


def fake_signed_exe() -> bytes:
    """Has a certificate table, but its contents are not a real signature."""
    return build_pe(PESpec(certificate=b"not a real pkcs7 signature".ljust(64, b"\0")))


def lnk_header() -> bytes:
    return bytes.fromhex("4C000000" "0114020000000000C000000000000046") + bytes(60)


def ooxml_zip(macros: bool = False) -> bytes:
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/document.xml", "<w:document/>")
        if macros:
            zf.writestr("word/vbaProject.bin", b"\0" * 16)
    return buf.getvalue()


def plain_zip() -> bytes:
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("readme.txt", "hello")
    return buf.getvalue()


def iso_header() -> bytes:
    return bytes(0x8001) + b"CD001" + bytes(0x800)


ALL = {
    "benign.exe": benign_exe,
    "benign.dll": benign_dll,
    "benign64.exe": benign_exe64,
    "suspicious.exe": suspicious_exe,
    "strings.exe": strings_exe,
    "fake_signed.exe": fake_signed_exe,
}


if __name__ == "__main__":
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "fixtures-out")
    out.mkdir(parents=True, exist_ok=True)
    for name, fn in ALL.items():
        (out / name).write_bytes(fn())
        print(out / name)
