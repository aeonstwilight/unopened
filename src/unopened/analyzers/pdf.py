"""PDF: JavaScript, OpenAction/additional actions, Launch actions, embedded files, URIs.

Two independent views:
1. A raw keyword scan over the bytes that decodes #xx-obfuscated names
   (e.g. /J#61vaScript), counting risky keywords whether or not the file parses.
2. pypdf for structure: JavaScript source (as text), what triggers it, Launch targets,
   embedded files (extracted with the bounded member writer and triaged recursively).

pypdf never renders or runs anything. Its decompression limits are lowered here, and its
optional external jbig2dec decoder is disabled so no program runs on sample data.
JavaScript is only read, deobfuscated as text and searched for keywords.
"""

from __future__ import annotations

import io
import re
from collections import Counter
from typing import Any

from ..deobfuscate import deobfuscate
from ..extraction import CHUNK, MemberWriter
from ..model import AnalyzerOutput, Finding, Severity
from . import Context
from .office import EXECUTABLE_EXTENSIONS
from .script import keyword_findings, scan_keywords

KEYWORDS = ["/JS", "/JavaScript", "/OpenAction", "/AA", "/Launch", "/EmbeddedFile",
            "/EmbeddedFiles", "/URI", "/AcroForm", "/XFA", "/RichMedia", "/ObjStm", "/Encrypt",
            "/SubmitForm", "/ImportData", "/GoToR", "/GoToE"]
NAME_RE = re.compile(rb"/[A-Za-z0-9#_.+-]{1,64}")
HEX_ESCAPE = re.compile(rb"#([0-9A-Fa-f]{2})")
MAX_OBJECTS = 200_000
MAX_JS_CHARS = 50_000
MAX_STREAM_OUTPUT = 50 * 1024 * 1024


def keyword_scan(data: bytes) -> tuple[dict[str, int], dict[str, int]]:
    counts: Counter[str] = Counter()
    obfuscated: Counter[str] = Counter()
    wanted = set(KEYWORDS)
    for m in NAME_RE.finditer(data):
        raw = m.group()
        name = HEX_ESCAPE.sub(lambda h: bytes([int(h.group(1), 16)]), raw).decode("latin-1")
        if name in wanted:
            counts[name] += 1
            if b"#" in raw:
                obfuscated[name] += 1
    return dict(counts), dict(obfuscated)


def _text(obj: Any) -> str:
    from pypdf.generic import StreamObject

    obj = obj.get_object() if hasattr(obj, "get_object") else obj
    if isinstance(obj, StreamObject):
        data = obj.get_data()
        for enc in ("utf-8", "latin-1"):
            try:
                return data.decode(enc)
            except UnicodeDecodeError:
                continue
    if isinstance(obj, bytes):
        return obj.decode("latin-1")
    return str(obj)


def analyze_pdf(ctx: Context) -> AnalyzerOutput:
    from pypdf import PdfReader, apply_configuration

    data = ctx.path.read_bytes()
    out = AnalyzerOutput()
    counts, obfuscated = keyword_scan(data)
    out.data = {
        "keywords": counts, "obfuscated_names": obfuscated, "javascript": [], "launch": [],
        "uris": [], "embedded": [], "encrypted": False, "objects_visited": 0,
    }
    writer = MemberWriter(ctx.extract_dir, ctx.options.limits, ctx.files_left, ctx.bytes_left)
    limit = min(MAX_STREAM_OUTPUT, ctx.options.limits.max_member_size)
    with apply_configuration(
        jbig2dec_binary=None,  # never call an external program on sample data
        zlib_maximum_output_length=limit,
        lzw_maximum_output_length=limit,
        run_length_maximum_output_length=limit,
        array_based_stream_maximum_output_length=limit,
        maximum_declared_stream_length=limit,
        image_maximum_buffer_size=limit,
    ):
        try:
            reader = PdfReader(io.BytesIO(data), strict=False)
            if reader.is_encrypted:
                out.data["encrypted"] = True
                if not reader.decrypt(""):
                    out.data["encrypted_unknown_password"] = True
                    raise _Stop
            _walk(reader, writer, out)
        except _Stop:
            pass
        except Exception as exc:
            out.errors.append(f"PDF structure: {type(exc).__name__}: {exc}")
    out.data["members"] = writer.members
    out.data["extracted_files"] = writer.used_files
    out.data["extracted_bytes"] = writer.used_bytes
    _findings(out, writer)
    return out


class _Stop(Exception):
    pass


def _walk(reader: Any, writer: MemberWriter, out: AnalyzerOutput) -> None:
    from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject

    root = reader.trailer
    stack: list[tuple[Any, bool, str]] = [(root, False, "trailer")]
    seen: set[tuple[int, int]] = set()
    visited = 0
    while stack:
        obj, auto, via = stack.pop()
        if isinstance(obj, IndirectObject):
            key = (obj.idnum, obj.generation)
            if key in seen:
                continue
            seen.add(key)
            try:
                obj = obj.get_object()
            except Exception as exc:
                out.errors.append(f"object {key[0]}: {type(exc).__name__}: {exc}")
                continue
        visited += 1
        if visited > MAX_OBJECTS:
            out.not_checked.append(f"PDF objects beyond the first {MAX_OBJECTS:,}")
            break
        if isinstance(obj, DictionaryObject):
            try:
                _inspect(obj, auto, via, writer, out)
            except Exception as exc:  # one odd object must not end the walk (M5 corpus 2)
                out.errors.append(f"object {via}: {type(exc).__name__}: {exc}")
            for k, v in obj.items():
                if k in ("/Parent", "/P"):
                    continue  # back-links; the target is reached from above anyway
                child_auto = auto or k in ("/OpenAction", "/AA")
                stack.append((v, child_auto, k if k in ("/OpenAction", "/AA") else via))
        elif isinstance(obj, ArrayObject):
            stack.extend((v, auto, via) for v in obj)
    out.data["objects_visited"] = visited


def _inspect(d: Any, auto: bool, via: str, writer: MemberWriter, out: AnalyzerOutput) -> None:
    action = d.get("/S")
    if action == "/JavaScript" and "/JS" in d:
        try:
            code = _text(d["/JS"])
        except Exception as exc:
            out.errors.append(f"JavaScript source: {type(exc).__name__}: {exc}")
            code = ""
        out.data["javascript"].append({
            "trigger": via if auto else "user action or name tree",
            "auto": auto, "length": len(code), "source": code[:MAX_JS_CHARS],
        })
    elif action == "/Launch":
        target = d.get("/F")
        win = d.get("/Win")
        entry = {"auto": auto, "target": _filespec_name(target) if target is not None else None}
        if win is not None:
            win = win.get_object()
            entry["windows_file"] = str(win.get("/F", "")) or None
            entry["parameters"] = str(win.get("/P", "")) or None
        out.data["launch"].append(entry)
    elif action == "/URI" and "/URI" in d:
        out.data["uris"].append(str(d["/URI"]))
    if d.get("/Type") == "/Filespec" or "/EF" in d:
        _embedded(d, writer, out)


def _filespec_name(spec: Any) -> str:
    spec = spec.get_object() if hasattr(spec, "get_object") else spec
    if hasattr(spec, "get"):
        for key in ("/UF", "/F", "/DOS", "/Unix"):
            if spec.get(key):
                return str(spec[key])
        return "unnamed"
    return str(spec)


def _embedded(spec: Any, writer: MemberWriter, out: AnalyzerOutput) -> None:
    name = _filespec_name(spec)
    ef = spec.get("/EF")
    if ef is None:
        return
    ef = ef.get_object()
    if not hasattr(ef, "get"):
        return  # /EF that is not an embedded-file dictionary (seen in IRS fill-in forms)
    stream_ref = ef.get("/UF") or ef.get("/F")
    if stream_ref is None:
        return
    stream = stream_ref.get_object()
    params = stream.get("/Params")
    declared = None
    if params is not None:
        size = params.get_object().get("/Size")
        declared = int(size) if size is not None else None
    record = {"name": name, "declared_size": declared}
    out.data["embedded"].append(record)
    sink = writer.open(name, declared, None, embedded_in="pdf")
    if sink is None:
        return
    try:
        with sink:
            payload = stream.get_data()  # bounded by the pypdf limits set above
            for i in range(0, len(payload), CHUNK):
                sink.write(payload[i:i + CHUNK])
    except Exception as exc:
        out.errors.append(f"embedded file {name}: {type(exc).__name__}: {exc}")


def _findings(out: AnalyzerOutput, writer: MemberWriter) -> None:
    d = out.data
    f = out.findings
    k = d["keywords"]
    if d["encrypted"]:
        if d.get("encrypted_unknown_password"):
            f.append(Finding(
                "pdf.encrypted", Severity.MEDIUM, "PDF is encrypted with a password",
                "Its objects could not be decrypted, so JavaScript, actions and attachments "
                "were not inspected (the keyword counts below come from the raw bytes).",
            ))
            out.not_checked.append("Contents of the password-protected PDF")
        else:
            f.append(Finding(
                "pdf.encrypted_empty_password", Severity.INFO,
                "PDF is encrypted with an empty password",
                "Common for documents that only restrict printing or copying; contents were "
                "decrypted and inspected.",
            ))
    scripts = d["javascript"]
    if scripts:
        f.append(Finding(
            "pdf.javascript", Severity.MEDIUM, f"Contains JavaScript ({len(scripts)} block(s))",
            "Ordinary documents rarely need scripts; PDF exploits and phishing PDFs use them.",
        ))
    if any(s["auto"] for s in scripts):
        f.append(Finding(
            "pdf.auto_javascript", Severity.HIGH, "JavaScript runs when the document is opened",
            "It is attached to an OpenAction or additional-action (/AA) trigger.",
        ))
    elif not scripts and (k.get("/JS") or k.get("/JavaScript")):
        f.append(Finding(
            "pdf.hidden_javascript", Severity.MEDIUM,
            "JavaScript keywords present but no script could be read",
            "The structure may be malformed or deliberately broken to hide the script from "
            "parsers.",
        ))
    for launch in d["launch"]:
        target = launch.get("windows_file") or launch.get("target") or "unknown"
        params = f" with parameters {launch['parameters']!r}" if launch.get("parameters") else ""
        f.append(Finding(
            "pdf.launch", Severity.HIGH, "Launch action can start a program",
            f"Target {target!r}{params}"
            + (", triggered on open" if launch["auto"] else "") + ".",
        ))
    for e in d["embedded"]:
        ext = e["name"].rsplit(".", 1)[-1].lower() if "." in e["name"] else ""
        risky = ext in EXECUTABLE_EXTENSIONS
        f.append(Finding(
            "pdf.embedded_executable" if risky else "pdf.embedded_file",
            Severity.HIGH if risky else Severity.MEDIUM, f"Embedded file: {e['name']}",
            ("It has an executable extension. " if risky else "")
            + "Attachments are extracted and analyzed below.",
        ))
    if d["uris"]:
        f.append(Finding(
            "pdf.uris", Severity.INFO, f"Links ({len(d['uris'])})",
            "Listed as indicators. Phishing PDFs are often just a link.",
        ))
    obf = d["obfuscated_names"]
    if obf:
        f.append(Finding(
            "pdf.obfuscated_names", Severity.MEDIUM, "Obfuscated PDF names",
            f"{', '.join(sorted(obf))} written with #xx escapes, which only makes sense to "
            "hide them from keyword scanners.",
        ))
    for key, fid, title in [("/XFA", "pdf.xfa", "XFA form"),
                            ("/RichMedia", "pdf.richmedia", "Rich media (Flash/video)")]:
        if k.get(key):
            f.append(Finding(fid, Severity.LOW, f"{title} present",
                             "Rarely needed, and a historical exploit vector."))
    texts: list[str] = list(d["uris"])
    for s in scripts:
        result = deobfuscate(s["source"])
        s["layers"] = [{"technique": x.technique, "count": x.count} for x in result.layers]
        if result.changed:
            s["deobfuscated"] = result.text[:MAX_JS_CHARS]
        hits = scan_keywords("javascript", [s["source"], result.text])
        f.extend(keyword_findings("pdf", hits, "the PDF's JavaScript"))
        texts += [line for line in result.text.splitlines() if line.strip()]
    for launch in d["launch"]:
        texts += [v for v in (launch.get("target"), launch.get("windows_file"),
                              launch.get("parameters")) if v]
    d["indicator_texts"] = [["pdf", t] for t in texts]
    if writer.stopped:
        out.not_checked.append(f"Attachments after the extraction limit ({writer.stopped})")
    for m in writer.members:
        if m.get("skipped"):
            out.not_checked.append(f"Attachment {m['name']} ({m['skipped']})")
