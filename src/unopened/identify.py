"""Identify a file's type from its content (magic bytes), never from its extension,
then flag file names that disagree with the content.

Only headers and, for ZIP, the central directory listing are read. Nothing is
extracted, decompressed, rendered or executed.
"""

from __future__ import annotations

import re
import struct
import unicodedata
import zipfile
from pathlib import Path

from .model import FileType, Mismatch, Severity

HEAD_SIZE = 0x9010  # enough to reach the ISO 9660 volume descriptors at 0x8001/0x8801/0x9001

OLE_MAGIC = bytes.fromhex("D0CF11E0A1B11AE1")
LNK_MAGIC = bytes.fromhex("4C000000") + bytes.fromhex("0114020000000000C000000000000046")
SEVENZIP_MAGIC = b"7z\xbc\xaf\x27\x1c"
VHD_MAGIC = b"conectix"  # VHD footer cookie (last 512 bytes; dynamic disks also copy it first)
VHDX_MAGIC = b"vhdxfile"

IMAGE_FILE_DLL = 0x2000
SUBSYSTEMS = {1: "native", 2: "GUI", 3: "console", 9: "Windows CE", 10: "EFI application"}
MACHINES = {0x14C: "x86", 0x8664: "x64", 0x1C0: "ARM", 0xAA64: "ARM64", 0x1C4: "ARMv7"}

# Expected extensions per content kind/subtype. Lowercase, without the dot.
PE_EXTS = {"exe", "dll", "sys", "scr", "cpl", "ocx", "drv", "efi", "mui", "ax", "com", "node"}
EXPECTED_EXTENSIONS: dict[str, set[str]] = {
    "pe": PE_EXTS,
    "mz": PE_EXTS,
    "ole": {"doc", "dot", "xls", "xlt", "xla", "ppt", "pot", "pps", "msi", "msg", "vsd", "pub",
            "mpp", "msp", "mst", "db"},
    "ole:word": {"doc", "dot", "wbk", "wiz"},
    "ole:excel": {"xls", "xlt", "xla", "xlw"},
    "ole:powerpoint": {"ppt", "pot", "pps", "ppa"},
    "ole:msi": {"msi", "msp", "mst", "msm"},
    "ole:outlook": {"msg", "oft"},
    "email:eml": {"eml", "mbox", "mht", "mhtml", "txt"},
    "ole:encrypted": {"docx", "docm", "xlsx", "xlsm", "xlsb", "pptx", "pptm", "doc", "xls", "ppt"},
    "ooxml:word": {"docx", "docm", "dotx", "dotm"},
    "ooxml:excel": {"xlsx", "xlsm", "xltx", "xltm", "xlam", "xlsb"},
    "ooxml:powerpoint": {"pptx", "pptm", "potx", "potm", "ppsx", "ppsm", "ppam"},
    "ooxml:other": {"docx", "docm", "xlsx", "xlsm", "pptx", "pptm", "vsdx", "xps", "oxps"},
    "zip": {"zip", "jar", "apk", "xpi", "nupkg", "whl", "vsix", "appx", "msix", "kmz", "epub",
            "odt", "ods", "odp", "crx", "cbz"},
    "lnk": {"lnk"},
    "pdf": {"pdf"},
    "7z": {"7z"},
    "iso": {"iso", "img"},
    "script:powershell": {"ps1", "psm1", "psd1"},
    "script:javascript": {"js", "jse", "mjs", "cjs"},
    "script:vbscript": {"vbs", "vbe", "vba"},
    "script:batch": {"bat", "cmd"},
    "html:html": {"html", "htm", "xhtml", "shtml", "shtm", "xht", "mht", "mhtml"},
    "html:hta": {"hta"},
    "svg": {"svg"},
    "wsf": {"wsf", "wsc", "sct"},
    # Word opens RTF under a .doc name without complaint; delivery uses that a lot.
    "rtf": {"rtf", "doc", "wri"},
    "vhd": {"vhd", "vhdx", "avhd", "avhdx"},
}

# Extensions a user would think of as "just a document/picture" and open without suspicion.
DOCUMENT_LIKE = {
    "pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "rtf", "txt", "csv",
    "jpg", "jpeg", "png", "gif", "bmp", "mp3", "mp4", "mov", "avi", "wav", "html", "htm", "odt",
}
# Extensions Windows will run, or hand to an interpreter, on double-click.
RUNNABLE = {
    "exe", "scr", "com", "pif", "cpl", "msi", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf",
    "wsh", "hta", "ps1", "lnk", "jar", "reg", "dll",
}
RUNNABLE_KINDS = {"pe", "mz", "lnk", "script", "wsf"}
# Extensions that claim a harmless, openable type. A program wearing one of these is
# disguised. Anything else (".bin", ".vir", ".malware", ".dat") is how samples are stored
# or transferred, which is worth noting but is not deception.
DECOY_EXTENSIONS = DOCUMENT_LIKE | {
    "zip", "rar", "7z", "gz", "tar", "iso", "img", "xml", "json", "eml", "msg", "svg", "webp",
    "ics", "vcf", "log",
}

RTLO_LIKE = {"‮", "‭", "‪", "‫", "⁦", "⁧", "⁨"}


def identify(path: Path, name: str | None = None) -> FileType:
    """Identify `path`. `name` is the name to check against the content when it differs
    from the file on disk (archive members are stored under index names)."""
    with path.open("rb") as f:
        head = f.read(HEAD_SIZE)
    file_type = _identify_content(path, head)
    if file_type.kind == "text":
        file_type = _script_by_name(name or path.name) or file_type
    elif file_type.kind == "html" and file_type.subtype == "html" and (
            name or path.name).lower().rstrip(". ").endswith(".hta"):
        # mshta runs any HTML under an .hta name with full user rights; the name decides.
        file_type = FileType("html", HTA_DESCRIPTION + " (identified by its .hta name)",
                             subtype="hta", details={"identified_by": "extension"})
    elif file_type.kind == "script":
        file_type = _script_language_by_name(name or path.name, file_type)
    file_type.mismatches = check_name(name or path.name, file_type)
    return file_type


def _script_by_name(name: str) -> FileType | None:
    """Text whose content heuristics found no language but whose name says script.

    M5 holdout: three real scripts were padded with junk so the heuristics, which read only
    the start of the file, scored nothing, and the script analyzer never ran. Text content
    cannot contradict a script extension, so the name decides."""
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    for key, exts in EXPECTED_EXTENSIONS.items():
        if key.startswith("script:") and ext in exts:
            lang = key.split(":", 1)[1]
            return FileType(
                "script",
                f"{SCRIPT_NAMES[lang]} script (identified by its .{ext} name; the content "
                "heuristics were inconclusive)",
                subtype=lang,
                details={"identified_by": "extension"},
            )
    return None


def _script_language_by_name(name: str, file_type: FileType) -> FileType:
    """Content heuristics found one script language and the name says another. When the
    content also shows signs of the named language, the name decides: it is what Windows
    will run the file with. M5 holdout set 2: two GuLoader VBScripts padded with junk
    scored higher as PowerShell, were analyzed with the PowerShell rules and came back
    "no findings"."""
    named = _script_by_name(name)
    if named is None or named.subtype == file_type.subtype:
        return file_type
    scores = (file_type.details or {}).get("heuristic_scores", {})
    if scores.get(named.subtype, 0) < 1:
        return file_type
    return FileType(
        "script",
        f"{SCRIPT_NAMES[named.subtype]} script (identified by its .{name.rsplit('.', 1)[-1]} "
        f"name; the content also scored as {SCRIPT_NAMES[file_type.subtype]})",
        subtype=named.subtype,
        details={"identified_by": "extension", "heuristic_scores": scores},
    )


def _identify_content(path: Path, head: bytes) -> FileType:
    if not head:
        return FileType("empty", "Empty file (0 bytes)")
    if head.startswith(b"MZ"):
        return _identify_mz(head)
    if head.startswith(OLE_MAGIC):
        return _identify_ole(path)
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return _identify_zip(path)
    if head.startswith(LNK_MAGIC):
        return FileType("lnk", "Windows shortcut (LNK)")
    if b"%PDF-" in head[:1024]:
        offset = head.find(b"%PDF-")
        details = {"header_offset": offset} if offset else {}
        return FileType("pdf", "PDF document", details=details)
    if head.startswith(SEVENZIP_MAGIC):
        return FileType("7z", "7-Zip archive")
    for offset in (0x8001, 0x8801, 0x9001):
        if head[offset : offset + 5] == b"CD001":
            return FileType("iso", "ISO 9660 disk image")
    if head.startswith(b"{\\rt"):
        # Word accepts any header starting {\rt, so {\rtf1 is not required (and exploit
        # documents often drop it to dodge scanners).
        return FileType("rtf", "Rich Text Format document (RTF)")
    if head.startswith(VHDX_MAGIC):
        return FileType("vhd", "Virtual hard disk (VHDX)", subtype="vhdx")
    if head.startswith(VHD_MAGIC) or _vhd_footer(path):
        return FileType("vhd", "Virtual hard disk (VHD)", subtype="vhd")
    if looks_like_email(head):
        return FileType("email", "Email message (.eml, RFC 5322)", subtype="eml")
    text = _decode_text(head)
    if text is not None:
        return _identify_text(text)
    return FileType("unknown", "Unrecognized binary data")


HEADER_LINE = re.compile(rb"^([A-Za-z][A-Za-z0-9-]{0,75}):[ \t]?")
KEY_HEADERS = {b"from", b"to", b"subject", b"date", b"received", b"mime-version",
               b"message-id", b"return-path", b"delivered-to", b"reply-to",
               b"x-mailer", b"authentication-results", b"dkim-signature", b"content-type"}
ANCHOR_HEADERS = {b"from", b"received", b"message-id", b"return-path", b"delivered-to"}


def looks_like_email(head: bytes) -> bool:
    """An RFC 5322 header block at the start of the file: header lines (with folded
    continuations) up to the first blank line, naming at least three of the usual message
    headers, one of them From, Received, Message-ID, Return-Path or Delivered-To. An
    mbox "From " separator line may come first."""
    lines = head[:65536].split(b"\n")
    if lines and lines[0].startswith(b"From "):
        lines = lines[1:]
    names: set[bytes] = set()
    count = 0
    for raw in lines[:400]:
        line = raw.rstrip(b"\r")
        if not line:
            break
        if b"\x00" in line:
            return False
        if line[:1] in (b" ", b"\t"):
            if count == 0:
                return False
            continue
        m = HEADER_LINE.match(line)
        if not m:
            return False
        names.add(m.group(1).lower())
        count += 1
    else:
        if count == 0:
            return False
    known = names & KEY_HEADERS
    return count >= 3 and len(known) >= 3 and bool(known & ANCHOR_HEADERS)


def _identify_mz(head: bytes) -> FileType:
    if len(head) < 0x40:
        return FileType("mz", "MZ header but file too short for a PE header (truncated?)")
    (e_lfanew,) = struct.unpack_from("<I", head, 0x3C)
    if e_lfanew + 24 > len(head) or head[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        return FileType(
            "mz", "MZ (DOS) executable without a valid PE header: DOS program or corrupt PE"
        )
    machine, _, _, _, _, opt_size, characteristics = struct.unpack_from(
        "<HHIIIHH", head, e_lfanew + 4
    )
    opt_off = e_lfanew + 24
    magic = struct.unpack_from("<H", head, opt_off)[0] if opt_off + 2 <= len(head) else 0
    fmt = {0x10B: "PE32", 0x20B: "PE32+"}.get(magic, "PE (unknown optional header)")
    subsystem = ""
    sub_off = opt_off + 68
    if opt_size >= 70 and sub_off + 2 <= len(head):
        subsystem = SUBSYSTEMS.get(struct.unpack_from("<H", head, sub_off)[0], "")
    is_dll = bool(characteristics & IMAGE_FILE_DLL)
    if subsystem == "native" and not is_dll:
        subtype, role = "driver", "driver or native image"
    else:
        subtype, role = ("dll", "DLL") if is_dll else ("exe", "executable")
    arch = MACHINES.get(machine, f"machine 0x{machine:04x}")
    sub = f", {subsystem}" if subsystem and subtype != "driver" else ""
    return FileType(
        "pe",
        f"{fmt} {role} ({arch}{sub})",
        subtype=subtype,
        details={"format": fmt, "machine": arch, "subsystem": subsystem, "is_dll": is_dll},
    )


MSI_CLSIDS = {"000c1084-0000-0000-c000-000000000046", "000c1086-0000-0000-c000-000000000046"}
OLE_DESCRIPTIONS = {
    "word": "Word 97-2003 document (OLE)",
    "excel": "Excel 97-2003 workbook (OLE)",
    "powerpoint": "PowerPoint 97-2003 presentation (OLE)",
    "msi": "Windows Installer package (MSI)",
    "outlook": "Outlook message (MSG)",
    "encrypted": "Encrypted Office document (OLE container)",
}


def _identify_ole(path: Path) -> FileType:
    generic = "OLE compound file (legacy Office document such as doc/xls/ppt, or MSI/MSG)"
    try:
        import olefile
    except ImportError:
        return FileType("ole", generic, details={"note": "olefile not installed; no subtype"})
    try:
        ole = olefile.OleFileIO(str(path))  # reads the CFB directory only
        try:
            names = {"/".join(p).lower() for p in ole.listdir(streams=True, storages=True)}
            clsid = (ole.root.clsid or "").lower() if ole.root else ""
        finally:
            ole.close()
    except Exception as exc:
        return FileType("ole", f"{generic}; directory unreadable", details={"error": str(exc)})
    if "encryptioninfo" in names and "encryptedpackage" in names:
        subtype = "encrypted"
    elif "worddocument" in names:
        subtype = "word"
    elif "workbook" in names or "book" in names:
        subtype = "excel"
    elif "powerpoint document" in names:
        subtype = "powerpoint"
    elif clsid in MSI_CLSIDS:
        subtype = "msi"
    elif any(n.startswith("__substg1.0_") for n in names):
        subtype = "outlook"
    else:
        return FileType("ole", generic, details={"streams": len(names)})
    has_macros = any(n.endswith("vba/dir") for n in names)
    macro = " with a VBA project (macros)" if has_macros else ""
    return FileType("ole", OLE_DESCRIPTIONS[subtype] + macro, subtype=subtype,
                    details={"streams": len(names), "vba_project": has_macros})


def _identify_zip(path: Path) -> FileType:
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()  # central directory only; nothing is decompressed
    except (zipfile.BadZipFile, OSError, ValueError) as exc:
        return FileType(
            "zip", "ZIP archive (central directory unreadable)", details={"error": str(exc)}
        )
    lowered = {n.lower() for n in names}
    extra = {}
    if "[content_types].xml" in lowered:
        has_macros = any(n.endswith("vbaproject.bin") for n in lowered)
        if any(n.startswith("word/") for n in lowered):
            subtype, app = "word", "Word"
        elif any(n.startswith("xl/") for n in lowered):
            subtype, app = "excel", "Excel"
        elif any(n.startswith("ppt/") for n in lowered):
            subtype, app = "powerpoint", "PowerPoint"
        elif not has_macros:
            # Same packaging format (Open Packaging Conventions) as Office, but a software
            # package: NuGet, VSIX, MSIX/APPX. Treated as a zip so its files are extracted
            # and analyzed. M5 benign corpus 2: PowerShell Gallery modules were otherwise
            # read as unknown Office documents and their scripts never examined.
            return FileType(
                "zip", "ZIP archive (Open Packaging Conventions package: NuGet, VSIX, "
                "MSIX/APPX or similar)",
                details={"members": len(names), "looks_like": "OPC package"},
            )
        else:
            subtype, app = "other", "Office Open XML"
        macro = " with a VBA project (macros)" if has_macros else ""
        return FileType(
            "ooxml",
            f"{app} document (OOXML){macro}",
            subtype=subtype,
            details={"members": len(names), "vba_project": has_macros},
        )
    if "meta-inf/manifest.mf" in lowered:
        extra["looks_like"] = "Java archive (JAR)"
    return FileType(
        "zip", "ZIP archive", details={"members": len(names), **extra}
    )


def utf16_without_bom(sample: bytes) -> str | None:
    """The codec of UTF-16 text saved without a byte-order mark, or None.

    Mostly-ASCII UTF-16 has a zero in nearly every odd byte (little-endian) or every even
    byte (big-endian), and almost none in the other. M5 holdout set 2: a GuLoader VBScript
    saved this way was reported as unrecognized binary data and never analyzed as a
    script."""
    if len(sample) < 16:
        return None
    even, odd = sample[0::2], sample[1::2]
    zeros_even, zeros_odd = even.count(0) / len(even), odd.count(0) / len(odd)
    if zeros_odd >= 0.6 and zeros_even <= 0.05:
        return "utf-16-le"
    if zeros_even >= 0.6 and zeros_odd <= 0.05:
        return "utf-16-be"
    return None


def _vhd_footer(path: Path) -> bool:
    try:
        size = path.stat().st_size
        if size < 512:
            return False
        with path.open("rb") as f:
            f.seek(size - 512)
            return f.read(8) == VHD_MAGIC
    except OSError:
        return False


def _decode_text(head: bytes) -> str | None:
    sample = head[:8192]
    if sample.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return sample.decode("utf-16", errors="strict")
        except UnicodeDecodeError:
            return sample[: len(sample) // 2 * 2].decode("utf-16", errors="replace")
    if b"\x00" in sample:
        codec = utf16_without_bom(sample)
        if codec is None:
            return None
        text = sample[: len(sample) // 2 * 2].decode(codec, errors="replace")
        return text if _text_ratio(text) >= 0.95 else None
    text = sample.decode("utf-8", errors="replace").lstrip("﻿")
    if _text_ratio(text) < 0.95:
        return None
    return text


def _text_ratio(text: str) -> float:
    """Share of characters that are not control codes. Format characters (zero-width
    spaces and joiners) and private-use characters are text: str.isprintable() rejects
    them, and M5 holdout set 2 had an 8.6 MB RemcosRAT JScript padded with them that was
    reported as unrecognized binary data."""
    controls = sum(1 for c in text
                   if unicodedata.category(c) == "Cc" and c not in "\r\n\t")
    return 1 - controls / max(len(text), 1)


SCRIPT_HINTS: dict[str, list[str]] = {
    "powershell": [
        r"\$env:", r"\bInvoke-[A-Z]\w+", r"-EncodedCommand\b", r"\bNew-Object\b",
        r"\[System\.[\w.]+\]", r"\bWrite-(?:Host|Output)\b", r"\bparam\s*\(", r"\bIEX\b",
        r"\b(?:Get|Set|New|Remove|Start|Stop)-[A-Z][a-zA-Z]+\b", r"\$\w+\s*=\s*",
        r"-(?:ExecutionPolicy|NoProfile|WindowStyle)\b",
    ],
    "javascript": [
        r"\bvar\s+\w+\s*=", r"\bfunction\s*\w*\s*\(", r"\bnew\s+ActiveXObject\b",
        r"\bWScript\.(?:CreateObject|Shell|Echo)", r"\beval\s*\(", r"\bString\.fromCharCode\b",
        r"\b(?:let|const)\s+\w+\s*=", r";\s*$",
    ],
    "vbscript": [
        r"(?im)^\s*Dim\s+\w+", r"(?i)\bSet\s+\w+\s*=\s*CreateObject\b", r"(?im)^\s*End\s+Sub\b",
        r"(?im)^\s*(?:Private\s+|Public\s+)?Sub\s+\w+", r"(?i)\bOn\s+Error\s+Resume\s+Next\b",
        r"(?i)\bWScript\.CreateObject\b", r"(?im)^\s*'", r"(?i)\bChr\(\d+\)\s*&",
    ],
    "batch": [
        r"(?im)^\s*@echo\s+off\b", r"%~dp0", r"(?im)^\s*goto\s+:?\w+", r"(?im)^\s*set\s+/[ap]\b",
        r"(?im)^\s*::", r"(?im)^\s*rem\s", r"(?im)^\s*if\s+(?:not\s+)?exist\b", r"%\w+%",
        r"(?im)^\s*(?:start|call)\s",
    ],
}
SCRIPT_NAMES = {
    "powershell": "PowerShell", "javascript": "JavaScript/JScript", "vbscript": "VBScript",
    "batch": "Windows batch",
}


JSON_START = re.compile(r'^\s*(?:\{\s*"|\[\s*[{\["\d\-]|\[\s*\])')


HTA_DESCRIPTION = "HTML Application (HTA, run by mshta.exe outside the browser)"
# Markup is recognized from what it starts with, after an XML declaration, comments and a
# doctype: a script that only mentions <html> in a string does not start with a tag.
MARKUP_PREAMBLE = re.compile(
    r"^(?:\s+|<\?xml[^>]*\?>|<!--.*?-->|<!doctype\s+(?!html)[^>]*>)*", re.I | re.S)
WSH_START = re.compile(r"<(?:job|package|scriptlet|component)\b", re.I)
HTML_START = re.compile(
    r"<(?:!doctype\s+html|html|head|body|script|meta|title|style|link|div|iframe|form|"
    r"center|table|p|a|img|span|h[1-6]|noscript|base|frameset|hta:application)[\s>/]", re.I)
HTA_TAG = re.compile(r"<hta:application\b", re.I)


def _identify_markup(text: str) -> FileType | None:
    rest = text[MARKUP_PREAMBLE.match(text).end():]
    if not rest.startswith("<"):
        return None
    if re.match(r"<svg[\s>]", rest, re.I):
        return FileType("svg", "SVG image (XML; can carry scripts and links)")
    if WSH_START.match(rest) and re.search(r"<script\b", text, re.I):
        return FileType("wsf", "Windows Script File (WSF/WSC, run by Windows Script Host)")
    if HTML_START.match(rest):
        if HTA_TAG.search(text):
            return FileType("html", HTA_DESCRIPTION, subtype="hta")
        return FileType("html", "HTML document", subtype="html")
    return None


def _identify_text(text: str) -> FileType:
    if markup := _identify_markup(text):
        return markup
    # JSON data names cmdlets and APIs as strings and scored as PowerShell. M5 corpus 2: a
    # PSScriptAnalyzer settings file listing Invoke-WebRequest, Invoke-Expression and
    # Start-Process was judged a malicious script. No script language starts like this.
    if JSON_START.match(text):
        return FileType("text", "JSON data", subtype="json")
    scores = {
        lang: sum(1 for p in patterns if re.search(p, text, re.MULTILINE))
        for lang, patterns in SCRIPT_HINTS.items()
    }
    best = max(scores, key=lambda k: scores[k])
    if scores[best] >= 2:
        return FileType(
            "script",
            f"{SCRIPT_NAMES[best]} script (identified by content heuristics)",
            subtype=best,
            details={"heuristic_scores": scores},
        )
    return FileType("text", "Plain text (no supported script language recognized)")


def _extension_key(file_type: FileType) -> str:
    if file_type.kind in ("ooxml", "script", "email", "html") or (
            file_type.kind == "ole" and file_type.subtype):
        return f"{file_type.kind}:{file_type.subtype}"
    return file_type.kind


def check_name(name: str, file_type: FileType) -> list[Mismatch]:
    """Compare the file name with the identified content."""
    mismatches: list[Mismatch] = []
    if any(c in RTLO_LIKE for c in name):
        visible = "".join(c for c in name if c not in RTLO_LIKE)
        mismatches.append(Mismatch(
            "identify.rtlo",
            Severity.HIGH,
            "File name contains a Unicode direction-override character, a trick used to make "
            f"the extension display reversed. Name without it: {visible!r}",
        ))
    clean = unicodedata.normalize("NFKC", "".join(c for c in name if c not in RTLO_LIKE))
    parts = clean.split(".")
    ext = parts[-1].strip().lower() if len(parts) > 1 else ""
    inner = parts[-2].strip().lower() if len(parts) > 2 else ""

    if inner in DOCUMENT_LIKE and ext in RUNNABLE:
        mismatches.append(Mismatch(
            "identify.double_extension",
            Severity.HIGH,
            f"Double extension: the name looks like a .{inner} file but the real extension is "
            f".{ext}. Windows hides known extensions by default, so users see only the decoy.",
        ))
    if len(parts) > 1 and re.search(r"\s{3,}$", parts[-2]):
        mismatches.append(Mismatch(
            "identify.padded_name",
            Severity.MEDIUM,
            "The name has a long run of spaces before the final extension, which can push the "
            "real extension out of view.",
        ))

    expected = EXPECTED_EXTENSIONS.get(_extension_key(file_type))
    if expected is None:
        return mismatches
    if not ext:
        mismatches.append(Mismatch(
            "identify.no_extension",
            Severity.INFO, f"File has no extension; content is {file_type.description}."
        ))
    elif ext not in expected:
        runnable = file_type.kind in RUNNABLE_KINDS and file_type.kind != "script"
        if runnable and ext in DECOY_EXTENSIONS:
            severity = Severity.HIGH
        elif file_type.kind == "script" or ext in DOCUMENT_LIKE:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW
        note = ("" if severity != Severity.LOW or not runnable else
                " The extension does not claim a harmless file type, so this is not a "
                "disguise; samples are often stored this way.")
        mismatches.append(Mismatch(
            "identify.extension_mismatch",
            severity,
            f"Extension .{ext} does not match the content: {file_type.description}. "
            f"Expected one of: {', '.join('.' + e for e in sorted(expected))}.{note}",
        ))
    return mismatches
