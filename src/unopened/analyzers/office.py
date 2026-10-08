"""Office documents: legacy OLE (doc/xls/ppt) and OOXML (docx/xlsm/...).

Uses oletools to extract and scan VBA macro source as text. Nothing is run:
- olevba's expression deobfuscation (which evaluates VBA string expressions) stays off;
- XLMMacroDeobfuscator (which emulates Excel 4.0 formulas) is disabled explicitly;
- OOXML members are read by this module with size and ratio limits (safezip) and handed
  to oletools as bytes, so a zip bomb never reaches a parser.
XML is parsed with defusedxml.
"""

from __future__ import annotations

import io
import re
import zipfile
from typing import Any

from ..model import AnalyzerOutput, Finding, Severity
from ..safezip import LimitExceeded, read_member
from . import Context

OLE_MAGIC = bytes.fromhex("D0CF11E0A1B11AE1")
MAX_MODULES = 50
MAX_SOURCE_CHARS = 20_000
MAX_EXCERPT_CHARS = 1_500
MAX_XLM_LINES = 200

EXECUTABLE_EXTENSIONS = {
    "exe", "scr", "com", "pif", "cpl", "dll", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf",
    "wsh", "hta", "ps1", "lnk", "jar", "msi", "reg", "sct", "chm", "iso", "img",
}
# Relationship types that make Office fetch remote content when the document opens.
REMOTE_LOAD_TYPES = {
    "attachedtemplate": "remote template",
    "oleobject": "remote OLE object",
    "frame": "remote frame",
    "subdocument": "remote sub-document",
    "externallinkpath": "external workbook link",
    "afchunk": "remote imported content",
}
DDE_RE = re.compile(r"(?i)\bDDE(?:AUTO)?\b")
W_NS = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
FIELD_PARTS = re.compile(r"(?i)^word/(document|header\d*|footer\d*|footnotes|endnotes)\.xml$")


def analyze_office(ctx: Context) -> AnalyzerOutput:
    from oletools import olevba

    olevba.XLMDEOBFUSCATOR = False  # never emulate XLM formulas
    out = AnalyzerOutput(data={
        "vba_projects": [], "modules": [], "autoexec": [], "suspicious": [], "iocs": [],
        "xlm_macros": False, "embedded": [], "external_relationships": [], "dde": [],
        "encrypted": False,
    })
    texts: list[str] = []
    if ctx.file_type.kind == "ooxml":
        _ooxml(ctx, out, texts)
    else:
        _ole(ctx, out, texts)
    _summarize(out)
    out.data["indicator_texts"] = [["office", t] for t in texts]
    return out


# VBA -----------------------------------------------------------------------------------

def _vba(data: bytes, label: str, out: AnalyzerOutput, texts: list[str]) -> None:
    from oletools import olevba

    if label.lower().endswith("vbaproject.bin") and not data.startswith(OLE_MAGIC):
        out.errors.append(f"{label}: not an OLE container, so its macros could not be read")
        out.data["vba_projects"].append(label)
        return
    try:
        parser = olevba.VBA_Parser(label, data=data, relaxed=True)
    except Exception as exc:
        out.errors.append(f"VBA in {label}: {type(exc).__name__}: {exc}")
        return
    try:
        if not parser.detect_vba_macros():
            return
        out.data["vba_projects"].append(label)
        for _sub, stream, vba_name, code in parser.extract_macros():
            if len(out.data["modules"]) >= MAX_MODULES:
                out.not_checked.append(f"VBA modules beyond the first {MAX_MODULES}")
                break
            code = code or ""
            out.data["modules"].append({
                "container": label, "stream": stream, "name": vba_name,
                "lines": code.count("\n") + 1, "source": code[:MAX_SOURCE_CHARS],
                "truncated": len(code) > MAX_SOURCE_CHARS,
            })
            texts.extend(line for line in code.splitlines() if line.strip())
        # deobfuscate=False: olevba must not evaluate VBA expressions.
        for kind, keyword, description in parser.analyze_macros(
                show_decoded_strings=False, deobfuscate=False):
            entry = {"keyword": keyword, "description": description}
            if kind == "AutoExec":
                out.data["autoexec"].append(entry)
            elif kind == "Suspicious":
                out.data["suspicious"].append(entry)
            elif kind == "IOC":
                out.data["iocs"].append(entry)
                texts.append(keyword)
        try:
            if parser.detect_vba_stomping():
                out.data["vba_stomping"] = True
        except Exception as exc:
            out.errors.append(f"VBA stomping check in {label}: {type(exc).__name__}: {exc}")
    finally:
        parser.close()


# Legacy OLE ----------------------------------------------------------------------------

def _ole(ctx: Context, out: AnalyzerOutput, texts: list[str]) -> None:
    import olefile
    from oletools import olevba

    data = ctx.path.read_bytes()
    ole = olefile.OleFileIO(io.BytesIO(data))
    try:
        streams = ["/".join(p) for p in ole.listdir(streams=True, storages=False)]
        lowered = {s.lower() for s in streams}
        if "encryptioninfo" in lowered or "encryptedpackage" in lowered:
            out.data["encrypted"] = True
        _ole_objects(ole, ctx.path.name, out, texts)
    finally:
        ole.close()
    _vba(data, ctx.path.name, out, texts)
    if ctx.file_type.subtype == "excel":
        try:
            parser = olevba.VBA_Parser(ctx.path.name, data=data, relaxed=True)
            try:
                if parser.detect_xlm_macros():  # plugin_biff: parses records, runs nothing
                    out.data["xlm_macros"] = True
                    lines = [str(x) for x in (parser.xlm_macros or [])][:MAX_XLM_LINES]
                    out.data["xlm_excerpt"] = lines
                    texts.extend(lines)
            finally:
                parser.close()
        except Exception as exc:
            out.errors.append(f"XLM macro check: {type(exc).__name__}: {exc}")
    if ctx.file_type.subtype == "word":
        out.not_checked.append("DDE fields in legacy binary Word documents")


def _ole_objects(ole: Any, container: str, out: AnalyzerOutput, texts: list[str]) -> None:
    from oletools import oleobj

    for path in ole.listdir(streams=True, storages=False):
        if path[-1].lower() != "\x01ole10native":
            continue
        name = "/".join(p.replace("\x01", "") for p in path)
        try:
            native = oleobj.OleNativeStream(ole.openstream(path).read())
        except Exception as exc:
            out.errors.append(f"embedded object {name}: {type(exc).__name__}: {exc}")
            continue
        entry = {
            "container": container, "stream": name, "kind": "OLE Package",
            "filename": native.filename, "source_path": native.src_path,
            "temp_path": native.temp_path, "size": native.native_data_size,
        }
        out.data["embedded"].append(entry)
        texts.extend(t for t in (native.src_path, native.temp_path) if t)


# OOXML ---------------------------------------------------------------------------------

def _ooxml(ctx: Context, out: AnalyzerOutput, texts: list[str]) -> None:
    import olefile
    from defusedxml import ElementTree

    limits = ctx.options.member_limits
    with zipfile.ZipFile(ctx.path) as zf:
        infos = zf.infolist()

        def read(info: zipfile.ZipInfo) -> bytes | None:
            try:
                return read_member(zf, info, limits)
            except LimitExceeded as exc:
                out.errors.append(str(exc))
                out.not_checked.append(f"Document part {info.filename} (not read: safety limit)")
            except (zipfile.BadZipFile, OSError, ValueError, NotImplementedError) as exc:
                out.errors.append(f"{info.filename}: {type(exc).__name__}: {exc}")
            return None

        for info in infos:
            name = info.filename
            low = name.lower()
            if low.endswith("vbaproject.bin"):
                if (blob := read(info)) is not None:
                    _vba(blob, name, out, texts)
            elif low.startswith("xl/macrosheets/"):
                out.data["xlm_macros"] = True
            elif low.endswith(".rels"):
                if (blob := read(info)) is not None:
                    _relationships(name, blob, ElementTree, out, texts)
            elif FIELD_PARTS.match(name):
                if (blob := read(info)) is not None:
                    _dde(name, blob, ElementTree, out, texts)
            if "/embeddings/" in low or "/activex/" in low:
                entry: dict[str, Any] = {"container": ctx.path.name, "stream": name,
                                         "kind": "ActiveX" if "/activex/" in low else "embedded",
                                         "size": info.file_size}
                if low.endswith(".bin") and "/embeddings/" in low:
                    blob = read(info)
                    if blob is not None and blob.startswith(OLE_MAGIC):
                        try:
                            ole = olefile.OleFileIO(io.BytesIO(blob))
                            try:
                                before = len(out.data["embedded"])
                                _ole_objects(ole, name, out, texts)
                                if len(out.data["embedded"]) > before:
                                    continue  # the package entries describe it better
                            finally:
                                ole.close()
                        except Exception as exc:
                            out.errors.append(f"embedded {name}: {type(exc).__name__}: {exc}")
                out.data["embedded"].append(entry)


def _relationships(part: str, blob: bytes, et: Any, out: AnalyzerOutput,
                   texts: list[str]) -> None:
    try:
        root = et.fromstring(blob)
    except Exception as exc:
        out.errors.append(f"{part}: unparseable XML ({type(exc).__name__}: {exc})")
        return
    for rel in root.iter():
        if not rel.tag.endswith("Relationship"):
            continue
        if (rel.get("TargetMode") or "").lower() != "external":
            continue
        rtype = (rel.get("Type") or "").rsplit("/", 1)[-1]
        target = rel.get("Target") or ""
        out.data["external_relationships"].append({"part": part, "type": rtype, "target": target})
        texts.append(target)


def _dde(part: str, blob: bytes, et: Any, out: AnalyzerOutput, texts: list[str]) -> None:
    try:
        root = et.fromstring(blob)
    except Exception as exc:
        out.errors.append(f"{part}: unparseable XML ({type(exc).__name__}: {exc})")
        return
    # Field codes are split across runs; join them in document order.
    fields, current = [], []
    for el in root.iter():
        if el.tag == f"{W_NS}fldChar":
            kind = el.get(f"{W_NS}fldCharType")
            if kind == "begin":
                current = []
            elif kind == "end" and current:
                fields.append("".join(current))
                current = []
        elif el.tag == f"{W_NS}instrText" and el.text:
            current.append(el.text)
        elif el.tag == f"{W_NS}fldSimple" and el.get(f"{W_NS}instr"):
            fields.append(el.get(f"{W_NS}instr"))
    if current:
        fields.append("".join(current))
    for field in fields:
        if DDE_RE.search(field):
            code = " ".join(field.split())
            out.data["dde"].append({"part": part, "field": code[:MAX_EXCERPT_CHARS]})
            texts.append(code)


# Findings ------------------------------------------------------------------------------

def _summarize(out: AnalyzerOutput) -> None:
    d = out.data
    f = out.findings
    if d["encrypted"]:
        f.append(Finding(
            "office.encrypted",
            Severity.MEDIUM, "Document is encrypted",
            "Its contents (including any macros) cannot be inspected without the password. "
            "Attackers encrypt documents to get past mail filters and share the password in "
            "the email.",
        ))
        out.not_checked.append("Contents of the encrypted document")
    if d["modules"]:
        f.append(Finding(
            "office.macros",
            Severity.MEDIUM, f"Contains VBA macros ({len(d['modules'])} module(s))",
            "Macros are programs inside the document. Most legitimate documents have none.",
        ))
    elif d["vba_projects"]:
        f.append(Finding(
            "office.vba_unreadable",
            Severity.MEDIUM, "Contains a VBA project, but no macro source could be read",
            "The project may be damaged or deliberately obscured.",
        ))
    if d["autoexec"]:
        words = ", ".join(sorted({a["keyword"] for a in d["autoexec"]}))
        f.append(Finding(
            "office.autoexec",
            Severity.HIGH, f"Macros run automatically ({words})",
            "Code runs as soon as the document is opened or content is enabled, without the "
            "user clicking anything else.",
        ))
    if d["suspicious"]:
        words = ", ".join(sorted({s["keyword"] for s in d["suspicious"]}))
        f.append(Finding(
            "office.suspicious_keywords",
            Severity.MEDIUM, "Macro code uses suspicious functions",
            f"{words}. These let a macro run programs, download files or hide its strings. "
            "Details are in the Office section.",
        ))
    if d.get("vba_stomping"):
        f.append(Finding(
            "office.vba_stomping",
            Severity.HIGH, "VBA stomping: macro source does not match the compiled code",
            "The readable source was replaced, so the code Office actually runs differs from "
            "what tools show. This is a deliberate anti-analysis trick.",
        ))
        out.not_checked.append("Compiled VBA p-code (the code that really runs) was not decompiled")
    if d["xlm_macros"]:
        f.append(Finding(
            "office.xlm",
            Severity.MEDIUM, "Excel 4.0 (XLM) macro sheet present",
            "An old macro language that runs from hidden sheets and is still abused because "
            "many tools overlook it.",
        ))
        out.not_checked.append("XLM macro logic (deobfuscation would require formula emulation)")
    for rel in d["external_relationships"]:
        what = REMOTE_LOAD_TYPES.get(rel["type"].lower())
        if what:
            f.append(Finding(
                "office.remote_load",
                Severity.HIGH, f"Document loads a {what} when opened",
                f"Target: {rel['target']}. Fetching remote content on open is how template "
                "injection delivers macros without them being in the file.",
            ))
    others = [r for r in d["external_relationships"]
              if r["type"].lower() not in REMOTE_LOAD_TYPES]
    if others:
        f.append(Finding(
            "office.external_links",
            Severity.INFO, f"External links ({len(others)})",
            "Links to outside resources, such as hyperlinks. They are listed as indicators.",
        ))
    for dde in d["dde"]:
        f.append(Finding(
            "office.dde",
            Severity.HIGH, "DDE field can run a command",
            f"Field code: {dde['field'][:300]}. Word may offer to run it when the document "
            "opens or its fields update.",
        ))
    for obj in d["embedded"]:
        if obj["kind"] != "OLE Package":
            continue
        ext = (obj.get("filename") or "").rsplit(".", 1)[-1].lower()
        risky = ext in EXECUTABLE_EXTENSIONS
        f.append(Finding(
            "office.embedded_executable" if risky else "office.embedded_file",
            Severity.HIGH if risky else Severity.MEDIUM,
            f"Embedded file: {obj.get('filename') or 'unnamed'}",
            ("It has an executable extension; double-clicking the icon in the document would "
             "run it. " if risky else "Users can open it by double-clicking its icon. ")
            + "Embedded files are not extracted or analyzed in this version.",
        ))
        out.not_checked.append(f"Embedded file {obj.get('filename') or obj['stream']} "
                               "(not extracted)")
    activex = [o for o in d["embedded"] if o["kind"] == "ActiveX"]
    if activex:
        f.append(Finding(
            "office.activex",
            Severity.LOW, f"ActiveX controls present ({len(activex)} part(s))",
            "ActiveX controls can carry auto-running event handlers.",
        ))
