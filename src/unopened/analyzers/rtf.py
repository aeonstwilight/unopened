"""RTF documents: embedded objects, the Equation Editor exploit, remote objects and
templates, header tricks.

oletools' rtfobj parses the RTF as text and decodes each \\objdata hex blob into its
OLE 1.0 object (class name, native data, Package filename); it emulates Word's own
parsing quirks, which exploit documents rely on to hide objects. Nothing is rendered or
run. Embedded files and OLE documents are written with the bounded member writer and
triaged recursively.
"""

from __future__ import annotations

import io
import re
from typing import Any

from ..extraction import MemberWriter
from ..model import AnalyzerOutput, Finding, Severity
from . import Context
from .office import EXECUTABLE_EXTENSIONS
from .web import sniff

MAX_RTF = 100 * 1024 * 1024
EQUATION_CLASSES = ("equation.3", "equation.2", "equation", "msequation")
# Class names and CLSIDs of objects that fetch their content from elsewhere.
LINK_CLASSES = ("ole2link", "url moniker", "soap moniker", "htmlfile")
OBJUPDATE = re.compile(rb"\\objupdate\b")
OBJ_AUTOLINK = re.compile(rb"\\objautlink\b|\\objlink\b")
REMOTE_TEMPLATE = re.compile(rb"\{\\\*\\template\s+((?:https?:|\\\\\\\\|//)[^}\s]{1,300})",
                             re.I)
URL_IN_OBJECT = re.compile(
    rb"h\x00t\x00t\x00p\x00s?\x00:\x00/\x00/\x00(?:[\x21-\x7e]\x00){1,200}"
    rb"|https?://[\x21-\x7e]{1,200}")
FONT_RECORD = 0x08
MAX_FONT_NAME = 32  # real equation font names ("Times New Roman", "Symbol") are short


def analyze_rtf(ctx: Context) -> AnalyzerOutput:
    from oletools import rtfobj

    out = AnalyzerOutput()
    with ctx.path.open("rb") as f:
        data = f.read(MAX_RTF + 1)
    if len(data) > MAX_RTF:
        out.not_checked.append(f"RTF beyond the first {MAX_RTF:,} bytes")
        data = data[:MAX_RTF]
    header = data[:16]
    out.data = {
        "header": header[:8].decode("latin-1"),
        "standard_header": data.startswith(b"{\\rtf1"),
        "objects": [],
        "objupdate": len(OBJUPDATE.findall(data)),
        "linked_objects": len(OBJ_AUTOLINK.findall(data)),
        "remote_template": None,
    }
    if m := REMOTE_TEMPLATE.search(data):
        out.data["remote_template"] = m.group(1).decode("latin-1")

    writer = MemberWriter(ctx.extract_dir, ctx.options.limits, ctx.files_left, ctx.bytes_left)
    try:
        parser = rtfobj.RtfObjParser(data)
        parser.parse()
        objects = parser.objects
    except Exception as exc:
        out.errors.append(f"RTF objects: {type(exc).__name__}: {exc}")
        objects = []
    for i, obj in enumerate(objects, 1):
        try:
            out.data["objects"].append(_object(i, obj, writer))
        except Exception as exc:
            out.errors.append(f"object {i}: {type(exc).__name__}: {exc}")
    out.data["members"] = writer.members
    out.data["extracted_files"] = writer.used_files
    out.data["extracted_bytes"] = writer.used_bytes
    _findings(out, writer)
    return out


def _text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.rstrip(b"\0").decode("latin-1")
    return str(value or "")


def _object(index: int, obj: Any, writer: MemberWriter) -> dict[str, Any]:
    rec: dict[str, Any] = {
        "index": index, "size": len(obj.rawdata or b""), "ole": bool(obj.is_ole),
        "class": _text(obj.class_name), "clsid": _text(obj.clsid),
        "clsid_description": _text(obj.clsid_desc), "package": bool(obj.is_package),
        "filename": None, "equation": None, "urls": [],
    }
    raw = obj.rawdata or b""
    rec["urls"] = sorted({u.replace(b"\x00", b"").decode("latin-1")
                          for u in URL_IN_OBJECT.findall(raw)})[:10]
    if obj.is_package:
        rec["filename"] = _text(obj.filename) or f"object-{index}.bin"
        rec["source_path"] = _text(obj.src_path)
        payload = obj.olepkgdata or b""
        writer.write_all(rec["filename"], [payload], len(payload), embedded_in="rtf",
                         object=index)
    elif obj.is_ole and obj.oledata:
        native = obj.oledata
        cls = rec["class"].lower()
        if cls.startswith(EQUATION_CLASSES) or "11882" in rec["clsid_description"]:
            rec["equation"] = _equation(native)
        kind = sniff(native)
        if kind and rec["equation"] is None:
            desc, ext, _ = kind
            name = f"object-{index}.{ext}"
            rec["filename"] = name
            writer.write_all(name, [native], len(native), embedded_in="rtf", object=index)
    elif raw and not obj.is_ole:
        rec["note"] = "object data is not a valid OLE 1.0 object (damaged or obfuscated)"
    return rec


def _equation(native: bytes) -> dict[str, Any]:
    """Look for the font-name overflow of CVE-2017-11882 / CVE-2018-0802 in Equation
    Editor data. The MTEF stream follows a 28-byte header in the 'Equation Native'
    stream; its FONT record holds a NUL-terminated name in a small fixed buffer."""
    import olefile

    result: dict[str, Any] = {"font_name_length": None, "overflow": False}
    stream = native
    if olefile.isOleFile(native):
        ole = olefile.OleFileIO(io.BytesIO(native))
        try:
            for entry in ole.listdir():
                if entry[-1].lower() == "equation native":
                    stream = ole.openstream(entry).read()
                    break
        finally:
            ole.close()
    if len(stream) >= 2:
        header_size = int.from_bytes(stream[:2], "little")
        mtef = stream[header_size:] if header_size == 0x1C else stream
    else:
        mtef = stream
    # MTEF: 5-byte header, then records; exploits put the FONT record first.
    for i in range(5, min(len(mtef), 64)):
        if mtef[i] == FONT_RECORD and i + 3 < len(mtef):
            name = mtef[i + 3:i + 3 + 512]
            end = name.find(b"\0")
            length = end if end >= 0 else len(name)
            result["font_name_length"] = length
            result["overflow"] = length > MAX_FONT_NAME
            break
    return result


def _findings(out: AnalyzerOutput, writer: MemberWriter) -> None:
    d = out.data
    f = out.findings
    if not d["standard_header"]:
        f.append(Finding(
            "rtf.malformed_header", Severity.MEDIUM, "Non-standard RTF header",
            f"The file starts {d['header']!r} instead of {{\\rtf1. Word accepts this; exploit "
            "documents use it to slip past scanners that look for the exact header.",
        ))
    if d["remote_template"]:
        f.append(Finding(
            "rtf.remote_template", Severity.HIGH, "RTF loads a remote template",
            f"Word fetches {d['remote_template']!r} when the document opens (template "
            "injection).",
        ))
    objects = d["objects"]
    for o in objects:
        label = o["class"] or "unknown class"
        if o["equation"] is not None:
            eq = o["equation"]
            if eq["overflow"]:
                f.append(Finding(
                    "rtf.equation_exploit", Severity.HIGH,
                    "Equation Editor exploit (CVE-2017-11882 / CVE-2018-0802)",
                    f"Object {o['index']} is an Equation Editor object whose font name is "
                    f"{eq['font_name_length']} bytes long; the editor copies it into a small "
                    "fixed buffer, so a long name overwrites the stack and runs the "
                    "attacker's code.",
                ))
            else:
                f.append(Finding(
                    "rtf.equation_object", Severity.MEDIUM, "Equation Editor object",
                    f"Object {o['index']} ({label}). Microsoft removed Equation Editor 3.0 "
                    "from Office in 2018 because of exploits; new documents do not contain "
                    "it, and exploit documents hide their payload in it.",
                ))
        elif o["package"]:
            name = o["filename"] or ""
            ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
            risky = ext in EXECUTABLE_EXTENSIONS
            f.append(Finding(
                "rtf.embedded_executable" if risky else "rtf.embedded_file",
                Severity.HIGH if risky else Severity.MEDIUM, f"Embedded file: {name}",
                ("It has an executable extension. " if risky else "")
                + "Packaged files are extracted and analyzed below.",
            ))
        elif label.lower().startswith(LINK_CLASSES) or "0199" in o["clsid_description"]:
            f.append(Finding(
                "rtf.remote_object", Severity.HIGH, "Object loads content from a remote server",
                f"Object {o['index']} ({label}) is a link object"
                + (f" pointing at {o['urls'][0]!r}" if o["urls"] else "")
                + ". This is how CVE-2017-0199 documents fetch and run an HTA.",
            ))
        elif o["ole"]:
            f.append(Finding(
                "rtf.embedded_object", Severity.MEDIUM, f"Embedded OLE object: {label}",
                "Documents can carry other documents and programs this way.",
            ))
    if d["objupdate"] and objects:
        f.append(Finding(
            "rtf.objupdate", Severity.MEDIUM, "Embedded objects update automatically on open",
            "\\objupdate makes Word load the object as soon as the document opens, without "
            "the user double-clicking it; exploit documents use it to trigger the payload.",
        ))
    unparsed = [o for o in objects if o.get("note")]
    if unparsed:
        f.append(Finding(
            "rtf.unparsed_object", Severity.MEDIUM,
            f"Object data that could not be decoded ({len(unparsed)})",
            "Damaged or deliberately obfuscated object data; its contents were not examined.",
        ))
        out.not_checked.append(f"Contents of {len(unparsed)} undecodable RTF object(s)")
    urls = sorted({u for o in objects for u in o["urls"]})
    d["indicator_texts"] = [["rtf", u] for u in urls] + (
        [["rtf", d["remote_template"]]] if d["remote_template"] else [])
    if writer.stopped:
        out.not_checked.append(f"Objects after the extraction limit ({writer.stopped})")
    for m in writer.members:
        if m.get("skipped"):
            out.not_checked.append(f"Embedded file {m['name']} ({m['skipped']})")
