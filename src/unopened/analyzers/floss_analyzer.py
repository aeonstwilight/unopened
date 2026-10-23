"""Decoded, stack and tight strings with FLOSS (PE files).

FLOSS finds functions that look like string decoders and emulates them in vivisect's
pure-Python emulator to recover the strings they produce; it also rebuilds strings
assembled on the stack. Like capa, nothing runs natively and the operating system never
loads the sample. Static strings are still extracted by the strings analyzer.

FLOSS output feeds the indicator list (source "floss") but not the verdict: until a
benign-corpus rerun shows these strings add no false positives, FLOSS only reports
(see docs/verdict-rules.md and M6 in CLAUDE.md).
"""

from __future__ import annotations

import logging
from typing import Any

from ..model import AnalyzerOutput, Finding, Severity
from . import Context

MAX_PER_KIND = 500
MAX_SAMPLE_SIZE = 16 * 1024 * 1024  # FLOSS's own default limit for deobfuscation
QUIET_LOGGERS = ("floss", "vivisect", "envi", "vtrace", "viv_utils")
KINDS = ("decoded", "stack", "tight")


def _is_dotnet(path: Any) -> bool:
    import pefile

    pe = pefile.PE(str(path), fast_load=True)
    try:
        d = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        return len(d) > 14 and d[14].VirtualAddress != 0
    finally:
        pe.close()


def analyze_floss(ctx: Context) -> AnalyzerOutput:
    out = AnalyzerOutput(data={kind: [] for kind in KINDS})
    if ctx.size > MAX_SAMPLE_SIZE:
        out.data["skipped"] = "file too large"
        out.not_checked.append(
            f"Decoded and stack strings: FLOSS does not deobfuscate files over "
            f"{MAX_SAMPLE_SIZE // (1024 * 1024)} MB"
        )
        return out
    if _is_dotnet(ctx.path):
        out.data["skipped"] = ".NET"
        out.not_checked.append("Decoded and stack strings: FLOSS does not emulate .NET code")
        return out

    for name in QUIET_LOGGERS:
        logging.getLogger(name).setLevel(logging.ERROR)
    import floss.identify as identify
    import floss.main as fm
    from floss.stackstrings import extract_stackstrings
    from floss.string_decoder import decode_strings
    from floss.tightstrings import extract_tightstrings

    min_length = max(ctx.options.min_string_length, 4)
    sigpaths = fm.get_signatures(ctx.options.capa_signatures) \
        if ctx.options.capa_signatures else []
    vw = fm.load_vw(ctx.path, "pe", sigpaths, should_save_workspace=False)
    functions = fm.select_functions(vw, None)
    features, _library = identify.find_decoding_function_features(
        vw, functions, disable_progress=True)

    stack = extract_stackstrings(
        vw, fm.get_functions_without_tightloops(features), min_length, disable_progress=True)
    tight = extract_tightstrings(
        vw, fm.get_functions_with_tightloops(features), min_length=min_length,
        disable_progress=True)
    candidates = fm.append_unique(
        identify.get_function_fvas(identify.get_top_functions(features, 20)),
        identify.get_tight_function_fvas(features))
    decoded = decode_strings(vw, candidates, min_length, disable_progress=True) \
        if candidates else []

    texts: list[str] = []
    for kind, items in (("decoded", decoded), ("stack", stack), ("tight", tight)):
        unique: dict[str, int] = {}
        for item in items:
            text = str(item.string)
            if text and text not in unique:
                fva = getattr(item, "function", None) or getattr(item, "decoding_routine", 0)
                unique[text] = int(fva or 0)
        if len(unique) > MAX_PER_KIND:
            out.not_checked.append(f"FLOSS {kind} strings beyond the first {MAX_PER_KIND:,}")
        for text, fva in list(unique.items())[:MAX_PER_KIND]:
            out.data[kind].append({"string": text, "function": f"0x{fva:x}"})
            texts.append(text)
    out.data["functions"] = len(functions)
    out.data["decoding_candidates"] = len(candidates)
    out.data["indicator_texts"] = [["floss", t] for t in texts]

    counts = {kind: len(out.data[kind]) for kind in KINDS}
    total = sum(counts.values())
    if total:
        out.findings.append(Finding(
            "floss.recovered", Severity.INFO,
            f"FLOSS recovered {total} hidden string(s)",
            f"{counts['decoded']} decoded, {counts['stack']} stack, {counts['tight']} tight. "
            "Programs build or decode strings at run time to keep them out of plain view; "
            "legitimate software does this too. They are listed in the FLOSS section and "
            "searched for indicators. FLOSS results do not affect the verdict yet.",
        ))
    return out
