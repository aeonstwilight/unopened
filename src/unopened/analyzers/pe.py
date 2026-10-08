"""PE basics with pefile: headers, compile timestamp, sections and entropy, imports of
interest, exports, debug (PDB) path, overlay and signature directory.

pefile only parses the file's bytes; it never loads or maps the image for execution.
"""

from __future__ import annotations

import math
import time
import tomllib
from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime
from functools import cache
from importlib import resources
from typing import Any

from ..identify import MACHINES
from ..model import AnalyzerOutput, Finding, Severity
from . import Context

HIGH_ENTROPY = 7.2
MIN_SECTION_FOR_ENTROPY = 1024
MAX_IMPORTS_RECORDED = 2000
MAX_EXPORTS_RECORDED = 500
MAX_WARNINGS = 50
# pefile warnings that restate checks reported separately (entropy, W+X, imports), or
# that fire on ordinary small files. Still kept in the data, but not raised as a finding.
REDUNDANT_WARNINGS = (
    "Byte 0x",
    "Suspicious flags set for section",
    "Imported symbols contain entries typical of packed executables",
)

SCN_CODE = 0x00000020
SCN_EXECUTE = 0x20000000
SCN_READ = 0x40000000
SCN_WRITE = 0x80000000

SUBSYSTEM_NAMES = {
    1: "Native (driver or boot-time)", 2: "Windows GUI", 3: "Windows console",
    9: "Windows CE GUI", 10: "EFI application", 11: "EFI boot service driver",
    12: "EFI runtime driver", 14: "Xbox", 16: "Windows boot application",
}

DELPHI_TIMESTAMP = 0x2A425E19  # 1992-06-19, set by old Borland/Delphi linkers
PLAUSIBLE_EARLIEST = datetime(1995, 1, 1, tzinfo=UTC)

PACKER_SECTIONS = {
    "upx0": "UPX", "upx1": "UPX", "upx2": "UPX", ".upx": "UPX", "upx!": "UPX",
    ".aspack": "ASPack", ".adata": "ASPack", ".nsp0": "NsPack", ".nsp1": "NsPack",
    ".mpress1": "MPRESS", ".mpress2": "MPRESS", ".petite": "Petite", ".themida": "Themida",
    ".winlice": "WinLicense", ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".vmp2": "VMProtect",
    ".enigma1": "Enigma", ".enigma2": "Enigma", "pec2": "PECompact", "pecompact2": "PECompact",
    ".perplex": "Perplex", ".pelock": "PELock", ".yp": "Y0da", ".ccg": "CCG", ".packed": "generic",
    ".rlpack": "RLPack", ".spack": "Simple Pack", ".mew": "MEW", "kkrunchy": "kkrunchy",
}


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


@cache
def import_categories() -> dict[str, dict[str, Any]]:
    text = resources.files("unopened").joinpath("data/pe_imports.toml").read_text("utf-8")
    return tomllib.loads(text)


def _matches(base: str, name: str) -> bool:
    return name == base or name == base + "A" or name == base + "W"


def analyze_pe(ctx: Context) -> AnalyzerOutput:
    import pefile

    out = AnalyzerOutput()
    try:
        pe = pefile.PE(str(ctx.path), fast_load=True)
    except pefile.PEFormatError as exc:
        raise ValueError(f"not a parseable PE file: {exc}") from exc
    try:
        steps: list[tuple[str, Callable[[], None]]] = [
            ("headers", lambda: _headers(pe, pefile, out)),
            ("sections", lambda: _sections(pe, ctx.size, out)),
            ("data directories", lambda: pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"],
            ])),
            ("imports", lambda: _imports(pe, out)),
            ("exports", lambda: _exports(pe, out)),
            ("debug info", lambda: _debug(pe, out)),
            ("signature directory", lambda: _security_dir(pe, ctx.size, out)),
            ("overlay", lambda: _overlay(pe, ctx, out)),
        ]
        for label, step in steps:
            try:
                step()
            except Exception as exc:  # one malformed structure must not hide the rest
                out.errors.append(f"{label}: {type(exc).__name__}: {exc}")
        warnings = pe.get_warnings()
        out.data["parser_warnings"] = warnings[:MAX_WARNINGS]
        anomalies = [w for w in warnings if not w.startswith(REDUNDANT_WARNINGS)]
        if anomalies:
            out.findings.append(Finding(
                "pe.header_anomalies",
                Severity.LOW, "PE structure has anomalies",
                f"The parser reported {len(anomalies)} problem(s) with malformed or unusual "
                f"headers, for example: {anomalies[0]} Malware sometimes tweaks headers to "
                "break analysis tools.",
            ))
    finally:
        pe.close()
    return out


def _headers(pe: Any, pefile: Any, out: AnalyzerOutput) -> None:
    fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
    is_64 = oh.Magic == 0x20B
    dll_chars = [
        name for name, value in pefile.dll_characteristics if oh.DllCharacteristics & value
    ]
    ts = fh.TimeDateStamp
    compiled = datetime.fromtimestamp(ts, UTC) if ts else None
    is_dotnet = (
        len(oh.DATA_DIRECTORY) > 14 and oh.DATA_DIRECTORY[14].VirtualAddress != 0
    )
    out.data["headers"] = {
        "format": "PE32+" if is_64 else "PE32",
        "machine": MACHINES.get(fh.Machine)
        or pefile.MACHINE_TYPE.get(fh.Machine, f"0x{fh.Machine:04x}"),
        "is_dll": pe.is_dll(),
        "subsystem": SUBSYSTEM_NAMES.get(oh.Subsystem)
        or pefile.SUBSYSTEM_TYPE.get(oh.Subsystem, str(oh.Subsystem)),
        "image_base": f"0x{oh.ImageBase:x}",
        "entry_point_rva": f"0x{oh.AddressOfEntryPoint:x}",
        "number_of_sections": fh.NumberOfSections,
        "linker_version": f"{oh.MajorLinkerVersion}.{oh.MinorLinkerVersion}",
        "dll_characteristics": dll_chars,
        "is_dotnet": is_dotnet,
        "compile_timestamp": ts,
        "compile_time_utc": compiled.isoformat() if compiled else None,
    }
    note = " It can also be a hash written by a reproducible-build linker, so treat it as a hint."
    if ts == 0:
        out.findings.append(Finding(
            "pe.timestamp_zeroed",
            Severity.LOW, "Compile timestamp is zeroed",
            "The build time was removed, which some builders do deliberately to hide it." + note,
        ))
    elif ts == DELPHI_TIMESTAMP:
        out.findings.append(Finding(
            "pe.timestamp_delphi",
            Severity.INFO, "Borland/Delphi default timestamp (1992-06-19)",
            "Typical of Delphi-built programs; the real build time is unknown.",
        ))
    elif compiled and compiled.timestamp() > time.time() + 86400:
        out.findings.append(Finding(
            "pe.timestamp_future",
            Severity.MEDIUM, "Compile timestamp is in the future",
            f"Claims to be built at {compiled.isoformat()}, so it was probably forged." + note,
        ))
    elif compiled and compiled < PLAUSIBLE_EARLIEST:
        out.findings.append(Finding(
            "pe.timestamp_old",
            Severity.LOW, "Implausibly old compile timestamp",
            f"Claims to be built at {compiled.isoformat()}, which is probably forged." + note,
        ))
    if is_dotnet:
        out.findings.append(Finding(
            "pe.dotnet",
            Severity.INFO, ".NET assembly",
            "The program's logic is in managed code, which this report does not decompile. "
            "Imports and sections say little about what a .NET program does.",
        ))
        out.not_checked.append(".NET managed code (decompilation is out of scope)")


def _section_name(raw: bytes) -> str:
    return raw.rstrip(b"\0").decode("latin-1")


def _sections(pe: Any, size: int, out: AnalyzerOutput) -> None:
    sections = []
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    ep_section = None
    for s in pe.sections:
        name = _section_name(s.Name)
        chars = s.Characteristics
        perms = (
            ("r" if chars & SCN_READ else "-")
            + ("w" if chars & SCN_WRITE else "-")
            + ("x" if chars & (SCN_EXECUTE | SCN_CODE) else "-")
        )
        ent = round(s.get_entropy(), 3)
        sections.append({
            "name": name,
            "virtual_address": f"0x{s.VirtualAddress:x}",
            "virtual_size": s.Misc_VirtualSize,
            "raw_size": s.SizeOfRawData,
            "entropy": ent,
            "permissions": perms,
        })
        end = s.PointerToRawData + s.SizeOfRawData
        if s.SizeOfRawData and end > size:
            missing = end - max(s.PointerToRawData, size)
            out.findings.append(Finding(
                "pe.truncated",
                Severity.MEDIUM, f"File is truncated: section {name} extends past the end",
                f"{missing:,} byte(s) of this section are missing from the file. The sample "
                "may be incomplete (partial download or carved from memory or disk).",
            ))
            out.not_checked.append(f"Section {name}: {missing:,} byte(s) missing from the file")
        if ep and s.contains_rva(ep):
            ep_section = (name, perms)
        lowered = name.lower()
        if lowered in PACKER_SECTIONS:
            out.findings.append(Finding(
                "pe.packer_section",
                Severity.MEDIUM, f"Packer section name: {name}",
                f"Section names like this are left by the {PACKER_SECTIONS[lowered]} packer. "
                "Packed programs hide their real code until they run.",
            ))
        if ent >= HIGH_ENTROPY and s.SizeOfRawData >= MIN_SECTION_FOR_ENTROPY:
            is_rsrc = lowered == ".rsrc"
            out.findings.append(Finding(
                "pe.high_entropy_section",
                Severity.LOW if is_rsrc else Severity.MEDIUM,
                f"High-entropy section: {name} ({ent:.2f} of 8.0)",
                "Data this random is usually compressed or encrypted"
                + (" (resources often hold compressed images, so this is weaker evidence)."
                   if is_rsrc else ", a common sign of packing."),
            ))
        if "w" in perms and "x" in perms:
            out.findings.append(Finding(
                "pe.wx_section",
                Severity.MEDIUM, f"Writable and executable section: {name}",
                "Code that can rewrite itself; typical of packers and self-decrypting malware.",
            ))
        if "x" in perms and s.SizeOfRawData == 0 and s.Misc_VirtualSize > 0:
            out.findings.append(Finding(
                "pe.empty_exec_section",
                Severity.LOW, f"Executable section with no data in the file: {name}",
                "It is filled in at run time, which is how many packers unpack their payload.",
            ))
    out.data["sections"] = sections
    if ep:
        if ep_section is None:
            out.findings.append(Finding(
                "pe.ep_outside_sections",
                Severity.MEDIUM, "Entry point is outside every section",
                f"Execution would start at RVA 0x{ep:x}, which no section covers. "
                "Normal compilers never do this.",
            ))
        elif "x" not in ep_section[1]:
            out.findings.append(Finding(
                "pe.ep_non_exec",
                Severity.MEDIUM, f"Entry point is in a non-executable section ({ep_section[0]})",
                "Normal compilers put the entry point in a code section.",
            ))
        out.data["entry_point_section"] = ep_section[0] if ep_section else None


def _imports(pe: Any, out: AnalyzerOutput) -> None:
    imports: dict[str, list[str]] = {}
    total = 0
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = entry.dll.decode("latin-1") if entry.dll else "?"
        names = []
        for imp in entry.imports:
            total += 1
            if total > MAX_IMPORTS_RECORDED:
                continue
            names.append(imp.name.decode("latin-1") if imp.name else f"ordinal {imp.ordinal}")
        imports.setdefault(dll, []).extend(names)
    out.data["imports"] = imports
    out.data["import_count"] = total
    if total > MAX_IMPORTS_RECORDED:
        out.not_checked.append(
            f"Imports beyond the first {MAX_IMPORTS_RECORDED} (of {total}) are not listed"
        )
    out.data["imphash"] = pe.get_imphash() or None

    all_names = {n for names in imports.values() for n in names}
    interesting: dict[str, list[str]] = {}
    for key, cat in import_categories().items():
        hits = sorted(n for n in all_names if any(_matches(b, n) for b in cat["functions"]))
        if hits:
            interesting[key] = hits
            out.findings.append(Finding(
                f"pe.imports.{key}",
                Severity(cat["severity"]), f"Imports: {cat['title']}",
                f"{cat['description']} Functions: {', '.join(hits)}. "
                "Legitimate software uses these too; treat this as a lead, not proof.",
            ))
    out.data["imports_of_interest"] = interesting

    is_dotnet = out.data.get("headers", {}).get("is_dotnet")
    if total == 0 and not pe.is_dll():
        out.findings.append(Finding(
            "pe.no_imports",
            Severity.MEDIUM, "No imports",
            "A Windows program with no imported functions must find them itself at run time, "
            "which is typical of packed code and shellcode loaders.",
        ))
    elif 0 < total <= 4 and not is_dotnet:
        out.findings.append(Finding(
            "pe.small_import_table",
            Severity.LOW, f"Very small import table ({total} function(s))",
            "Packed programs often import only what they need to unpack the rest.",
        ))


def _exports(pe: Any, out: AnalyzerOutput) -> None:
    exp = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if exp is None:
        return
    names = [
        s.name.decode("latin-1") if s.name else f"ordinal {s.ordinal}" for s in exp.symbols
    ]
    out.data["export_dll_name"] = exp.name.decode("latin-1") if exp.name else None
    out.data["exports"] = names[:MAX_EXPORTS_RECORDED]
    out.data["export_count"] = len(names)


def _debug(pe: Any, out: AnalyzerOutput) -> None:
    for dbg in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
        entry = getattr(dbg, "entry", None)
        pdb = getattr(entry, "PdbFileName", None)
        if pdb:
            out.data["pdb_path"] = pdb.rstrip(b"\0").decode("utf-8", errors="replace")
            return


def _security_dir(pe: Any, size: int, out: AnalyzerOutput) -> None:
    d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]  # IMAGE_DIRECTORY_ENTRY_SECURITY: a file offset
    present = d.VirtualAddress != 0 and d.Size != 0
    info = {"present": present, "offset": d.VirtualAddress, "size": d.Size}
    if present and d.VirtualAddress + d.Size > size:
        info["truncated"] = True
        out.findings.append(Finding(
            "pe.signature_dir_truncated",
            Severity.MEDIUM, "Signature directory points past the end of the file",
            "The file is truncated or its signature directory was tampered with.",
        ))
    out.data["signature_directory"] = info


def _overlay(pe: Any, ctx: Context, out: AnalyzerOutput) -> None:
    start = pe.get_overlay_data_start_offset()
    if start is None or start >= ctx.size:
        return
    end = ctx.size
    sig = out.data.get("signature_directory", {})
    if sig.get("present") and sig["offset"] >= start:
        # The certificate table lives after the sections but is not an overlay.
        if sig["offset"] == start:
            start = min(sig["offset"] + sig["size"], ctx.size)
        else:
            end = sig["offset"]
    size = max(end - start, 0)
    if size == 0:
        return
    with ctx.path.open("rb") as f:
        f.seek(start)
        sample = f.read(min(size, 8 << 20))
    ent = round(entropy(sample), 3)
    out.data["overlay"] = {"offset": start, "size": size, "entropy": ent}
    share = size / ctx.size
    severity = Severity.LOW if share > 0.5 or ent >= HIGH_ENTROPY else Severity.INFO
    out.findings.append(Finding(
        "pe.overlay",
        severity, f"Data appended after the PE image (overlay, {size:,} bytes)",
        f"{share:.0%} of the file, entropy {ent:.2f}. Installers keep archives here; droppers "
        "hide payloads here.",
    ))
