from __future__ import annotations

from .. import hashing
from ..model import AnalyzerOutput
from . import Context


def analyze_hashes(ctx: Context) -> AnalyzerOutput:
    return AnalyzerOutput(data=hashing.crypto_hashes(ctx.path))


def analyze_tlsh(ctx: Context) -> AnalyzerOutput:
    if ctx.size < hashing.TLSH_MIN_BYTES:
        return AnalyzerOutput(
            data={"tlsh": None},
            not_checked=[f"TLSH needs at least {hashing.TLSH_MIN_BYTES} bytes; file is {ctx.size}"],
        )
    digest = hashing.tlsh_hash(ctx.path)
    if digest is None:
        return AnalyzerOutput(
            data={"tlsh": None},
            not_checked=["TLSH: the data is too uniform to produce a fuzzy hash"],
        )
    return AnalyzerOutput(data={"tlsh": digest})
