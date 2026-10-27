"""Analyzer registry.

Each analyzer is a plain function taking a Context and returning an AnalyzerOutput. The
runner decides whether it applies, whether its optional libraries are installed, and
runs it in a worker process with a timeout. Analyzers parse bytes; none may execute,
load or render the sample.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from ..extraction import Limits
from ..indicators.allowlist import Allowlist
from ..model import AnalyzerOutput, FileType
from ..safezip import MemberLimits

DEFAULT_TIMEOUTS = {"capa": 300.0, "capa_file_scope": 60.0, "floss": 180.0}


class AnalyzerUnavailable(Exception):
    """Raised by an analyzer when an optional dependency is installed but unusable."""


@dataclass(frozen=True)
class Options:
    min_string_length: int = 5
    max_strings: int = 200_000
    max_indicators: int = 5_000
    timeout: float = 60.0
    timeouts: dict[str, float] = field(default_factory=lambda: dict(DEFAULT_TIMEOUTS))
    # Whole-file budget, archive members included. Analyzer limits alone add up: in M5 one
    # benign file took 1,356 s although no single analyzer may run past 300 s.
    file_timeout: float = 900.0
    allowlist: Allowlist = field(default_factory=Allowlist)
    yara_rules: Path | None = None
    capa_rules: Path | None = None
    capa_signatures: Path | None = None
    member_limits: MemberLimits = field(default_factory=MemberLimits)
    limits: Limits = field(default_factory=Limits)
    archive_passwords: tuple[str, ...] = ("infected",)
    reputation: bool = False  # opt-in network lookups, hashes only
    max_lookups: int = 20
    hunt: bool = True
    hunt_days: int = 30

    def timeout_for(self, analyzer: str) -> float:
        return self.timeouts.get(analyzer, self.timeout)


@dataclass(frozen=True)
class Context:
    path: Path
    file_type: FileType
    options: Options
    size: int
    depth: int = 0
    extract_dir: Path | None = None  # None: do not extract (depth limit or not an archive)
    files_left: int = 0
    bytes_left: int = 0


@dataclass(frozen=True)
class Analyzer:
    name: str
    title: str  # what the check is, as listed under "Not checked" when it does not run
    func: Callable[[Context], AnalyzerOutput]
    # File kinds this analyzer applies to, as "kind" or "kind:subtype" ("ole:outlook").
    # None: applies to every file.
    kinds: frozenset[str] | None = None
    requires: tuple[str, ...] = ()  # importable module names
    install_hint: str = ""
    # Cheaper analyzer run in its place when this one times out. Its result replaces the
    # timeout, marked PARTIAL, so the report shows what was checked and what was not.
    fallback: Analyzer | None = None


def type_keys(file_type: FileType) -> set[str]:
    """The keys an Analyzer.kinds set can name for this file type."""
    keys = {file_type.kind}
    if file_type.subtype:
        keys.add(f"{file_type.kind}:{file_type.subtype}")
    return keys


def registry() -> list[Analyzer]:
    from . import (
        archive,
        authenticode,
        basic,
        capa_analyzer,
        disk,
        floss_analyzer,
        lnk,
        mail,
        office,
        pdf,
        pe,
        rtf,
        script,
        strings,
        web,
        yara_scan,
    )

    return [
        Analyzer("hashes", "Cryptographic hashes (MD5, SHA1, SHA256)", basic.analyze_hashes),
        Analyzer(
            "tlsh", "Fuzzy hash (TLSH)", basic.analyze_tlsh,
            requires=("tlsh",), install_hint="pip install 'unopened[fuzzy]'",
        ),
        Analyzer(
            "pe", "PE structure (headers, sections, imports, imphash)", pe.analyze_pe,
            kinds=frozenset({"pe", "mz"}), requires=("pefile",), install_hint="pip install pefile",
        ),
        Analyzer(
            "authenticode", "Authenticode signature presence and validity",
            authenticode.analyze_authenticode,
            kinds=frozenset({"pe"}), requires=("signify",), install_hint="pip install signify",
        ),
        Analyzer(
            "capa", "Capabilities mapped to MITRE ATT&CK (capa)", capa_analyzer.analyze_capa,
            kinds=frozenset({"pe"}), requires=("capa",),
            install_hint="pip install 'unopened[capa]'",
            fallback=Analyzer(
                "capa_file_scope", "Capabilities from file-level capa rules only",
                capa_analyzer.analyze_capa_file_scope, kinds=frozenset({"pe"}),
                requires=("capa",),
            ),
        ),
        Analyzer(
            "floss", "Decoded and stack strings (FLOSS)", floss_analyzer.analyze_floss,
            kinds=frozenset({"pe"}), requires=("floss",),
            install_hint="pip install 'unopened[floss]'",
        ),
        Analyzer(
            "office", "Office macros, auto-run triggers, embedded objects and external references",
            office.analyze_office,
            kinds=frozenset({"ole", "ooxml"}), requires=("oletools", "olefile", "defusedxml"),
            install_hint="pip install 'unopened[office]'",
        ),
        Analyzer(
            "lnk", "Shortcut target, arguments and LOLBin use", lnk.analyze_lnk,
            kinds=frozenset({"lnk"}), requires=("LnkParse3",),
            install_hint="pip install 'unopened[lnk]'",
        ),
        Analyzer(
            "email", "Email headers, sender authentication, links and attachments",
            mail.analyze_email, kinds=frozenset({"email", "ole:outlook"}),
        ),
        Analyzer(
            "archive", "Archive and disk image members", archive.analyze_archive,
            kinds=frozenset({"zip", "7z", "iso"}),
        ),
        Analyzer(
            "script", "Script deobfuscation and keywords", script.analyze_script,
            kinds=frozenset({"script"}),
        ),
        Analyzer(
            "pdf", "PDF JavaScript, actions and embedded files", pdf.analyze_pdf,
            kinds=frozenset({"pdf"}), requires=("pypdf",),
            install_hint="pip install 'unopened[pdf]'",
        ),
        Analyzer(
            "web", "HTML, SVG, HTA and WSF: smuggled payloads, redirects, forms and scripts",
            web.analyze_web, kinds=frozenset({"html", "svg", "wsf"}),
        ),
        Analyzer(
            "rtf", "RTF embedded objects, Equation Editor exploit and remote content",
            rtf.analyze_rtf, kinds=frozenset({"rtf"}), requires=("oletools", "olefile"),
            install_hint="pip install 'unopened[office]'",
        ),
        Analyzer(
            "vhd", "Virtual hard disk (VHD/VHDX) header", disk.analyze_vhd,
            kinds=frozenset({"vhd"}),
        ),
        Analyzer(
            "yara", "YARA rule scan", yara_scan.analyze_yara,
            requires=("yara",), install_hint="pip install 'unopened[yara]'",
        ),
        Analyzer("strings", "Strings and indicator extraction", strings.analyze_strings),
    ]
