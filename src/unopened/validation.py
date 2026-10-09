"""Validation harness (milestone M5).

Runs triage over a directory of samples, compares each result with an expectations CSV,
and writes a results CSV and a Markdown summary. Built to run inside the analysis VM;
only those two text files (and, optionally, the JSON reports) are meant to leave it.

Safety: triage runs in-process through the normal CLI path, so every hard rule that
applies to `unopened triage` applies here too. This module never executes, opens or
renders a sample, and never touches the network. Its outputs carry counts, finding IDs,
rule IDs and behavior labels only, never raw indicator values. Hunt queries are turned
off because they carry paste-ready (raw) indicators.

Expectations CSV columns (header required; extra columns are ignored):

    sha256,name,label,expected_verdict,expected_behaviors,notes

- sha256 or name identifies the sample. A sample inside an archive is matched too, so a
  lab zip can be triaged as one file and each member still compared with its own row.
- label: malicious or benign.
- expected_verdict: one or more of malicious, suspicious, no findings, could not
  analyze, separated by "|". Empty means "anything".
- expected_behaviors: behavior labels from BEHAVIORS, separated by ";".
"""

from __future__ import annotations

import argparse
import contextlib
import csv
import hashlib
import io
import json
import statistics
import sys
import tempfile
import time
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import __version__, cli

VERDICTS = ("malicious", "suspicious", "could not analyze", "no findings")
INCOMPLETE = {"partial", "error", "timeout", "unavailable"}
RESERVED_TRIAGE_ARGS = {"--format", "--out", "--reputation"}


# --- Evidence ---------------------------------------------------------------------------

@dataclass
class Evidence:
    """What one report (and everything extracted from it) showed, reduced to labels."""

    finding_ids: set[str] = field(default_factory=set)
    capa_names: set[str] = field(default_factory=set)
    capa_namespaces: set[str] = field(default_factory=set)
    attack_tactics: set[str] = field(default_factory=set)
    indicator_types: set[str] = field(default_factory=set)
    import_categories: set[str] = field(default_factory=set)
    imported: set[str] = field(default_factory=set)
    subtypes: set[str] = field(default_factory=set)

    def merge(self, other: Evidence) -> None:
        for name in self.__dataclass_fields__:
            getattr(self, name).update(getattr(other, name))

    def ns(self, *prefixes: str) -> bool:
        return any(n.startswith(p) for n in self.capa_namespaces for p in prefixes)

    def capa(self, *words: str) -> bool:
        return any(w in n.lower() for n in self.capa_names for w in words)

    def imports(self, *names: str) -> bool:
        return any(i.lower().startswith(n.lower()) for i in self.imported for n in names)

    def found(self, *ids: str) -> bool:
        return bool(self.finding_ids.intersection(ids))


def evidence_of(report: dict[str, Any], include_members: bool = True) -> Evidence:
    ev = Evidence()
    ev.finding_ids.update(f["id"] for f in report.get("findings", []))
    ident = report.get("identification") or {}
    ev.finding_ids.update(m["id"] for m in ident.get("mismatches", []))
    if ident.get("subtype"):
        ev.subtypes.add(str(ident["subtype"]))
    analyzers = report.get("analyzers", {})
    for cap in (analyzers.get("capa", {}).get("data") or {}).get("capabilities", []):
        ev.capa_names.add(cap.get("name", ""))
        ev.capa_namespaces.add(cap.get("namespace", ""))
        ev.attack_tactics.update(a.get("tactic", "") for a in cap.get("attack", []))
    pe_data = analyzers.get("pe", {}).get("data") or {}
    ev.import_categories.update(pe_data.get("imports_of_interest", {}))
    ev.imported.update(n for names in (pe_data.get("imports") or {}).values() for n in names)
    ev.indicator_types.update(i.get("type", "") for i in report.get("indicators", []))
    if include_members:
        for child in report.get("members", []):
            ev.merge(evidence_of(child["report"]))
    return ev


# --- Behaviors --------------------------------------------------------------------------
# Each label maps to what counts as the report having surfaced that behavior. A behavior
# that the code really has can still be invisible statically (packed or encrypted code);
# that shows as a miss with an explanation in docs/validation.md, not as a test failure.

NETWORK_TYPES = {"url", "domain", "ipv4", "ipv6"}

BEHAVIORS: dict[str, tuple[str, Callable[[Evidence], bool]]] = {
    "packed": ("Packed or encrypted code", lambda e: e.found(
        "pe.packer_section", "pe.high_entropy_section", "pe.no_imports", "pe.small_import_table",
        "pe.wx_section", "pe.ep_non_exec", "pe.empty_exec_section", "capa.limited")
        or e.ns("anti-analysis/packer")),
    "network": ("Network communication", lambda e: "network" in e.import_categories
        or e.ns("communication/") or bool(e.indicator_types & NETWORK_TYPES)),
    "network_indicator": ("A URL, domain or IP address to pivot on",
                          lambda e: bool(e.indicator_types & NETWORK_TYPES)),
    "download": ("Downloads content", lambda e: e.imports("URLDownloadTo")
        or e.capa("download") or e.found("script.download_execute", "behavior.download_execute")),
    "persistence": ("Persistence (Run key, service, startup)", lambda e: "persistence"
        in e.import_categories or e.found("indicators.persistence_registry")
        or e.ns("persistence/") or "Persistence" in e.attack_tactics
        or e.found("behavior.run_key_persistence")),
    "service": ("Installs or changes a service", lambda e: e.imports(
        "CreateService", "ChangeServiceConfig", "StartServiceCtrlDispatcher")
        or e.capa("service")),
    "registry": ("Reads or writes the registry", lambda e: "registry_key" in e.indicator_types
        or e.imports("RegSetValue", "RegCreateKey") or e.ns("host-interaction/registry")),
    "injection": ("Process injection or replacement", lambda e: "process_injection"
        in e.import_categories or e.ns("host-interaction/process/inject")
        or e.capa("inject", "hollow")),
    "execution": ("Starts programs or commands", lambda e: "execution" in e.import_categories
        or e.capa("create process", "execute shell command")),
    "keylogging": ("Keystroke capture", lambda e: "input_capture" in e.import_categories
        or e.ns("collection/keylog") or e.capa("keystroke", "keylog")
        or e.found("behavior.keylogger")),
    "anti_analysis": ("Debugger or VM detection", lambda e: "anti_analysis"
        in e.import_categories or e.ns("anti-analysis/")),
    "encoding": ("Encodes or encrypts data", lambda e: "crypto" in e.import_categories
        or e.ns("data-manipulation/encoding", "data-manipulation/encryption")),
    "embedded_payload": ("Carries another program (resource, overlay or member)", lambda e:
        e.found("pe.overlay", "container.runnable_member", "office.embedded_executable",
                "pdf.embedded_file") or e.capa("embedded pe", "resource")
        or e.ns("executable/resource")),
    "dynamic_resolution": ("Resolves APIs at run time", lambda e: "dynamic_resolution"
        in e.import_categories or e.ns("linking/runtime-linking")),
    "mutex": ("Uses a mutex (single-instance marker)", lambda e: e.capa("mutex")),
    "file_write": ("Writes, copies or deletes files", lambda e: e.capa(
        "write file", "copy file", "delete file", "move file")
        or e.imports("CopyFile", "MoveFile", "DeleteFile")),
    "discovery": ("Enumerates files, processes or the host", lambda e: "discovery"
        in e.import_categories or "Discovery" in e.attack_tactics),
    "privilege": ("Adjusts token privileges", lambda e: "privilege" in e.import_categories
        or e.capa("privilege")),
    "macro_autoexec": ("Macro that runs on open", lambda e: e.found("office.autoexec")),
    "lnk_lolbin": ("Shortcut that launches a LOLBin", lambda e: e.found(
        "lnk.lolbin_target", "lnk.lolbin_argument", "lnk.encoded_powershell")),
    "script_obfuscation": ("Obfuscated script", lambda e: e.found("script.obfuscated")),
    "pdf_javascript": ("PDF JavaScript", lambda e: e.found(
        "pdf.javascript", "pdf.auto_javascript", "pdf.hidden_javascript")),
    "dll": ("Is a DLL", lambda e: "dll" in e.subtypes),
}


# --- Expectations -----------------------------------------------------------------------

class ExpectationError(ValueError):
    pass


@dataclass
class Expectation:
    sha256: str
    name: str
    label: str
    verdicts: tuple[str, ...]
    behaviors: tuple[str, ...]
    notes: str = ""


def load_expectations(path: Path) -> list[Expectation]:
    rows: list[Expectation] = []
    with path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(line for line in f if not line.lstrip().startswith("#"))
        missing = {"label"} - set(reader.fieldnames or [])
        if missing or not {"sha256", "name"} & set(reader.fieldnames or []):
            raise ExpectationError(f"{path}: needs a header with label and sha256 or name")
        for n, row in enumerate(reader, start=2):
            sha = (row.get("sha256") or "").strip().lower()
            name = (row.get("name") or "").strip()
            if not sha and not name:
                raise ExpectationError(f"{path} row {n}: needs sha256 or name")
            label = (row.get("label") or "").strip().lower()
            if label not in ("malicious", "benign"):
                raise ExpectationError(f"{path} row {n}: label must be malicious or benign")
            verdicts = tuple(v.strip().lower() for v in
                             (row.get("expected_verdict") or "").split("|") if v.strip())
            bad = [v for v in verdicts if v not in VERDICTS]
            if bad:
                raise ExpectationError(f"{path} row {n}: unknown verdict {bad[0]!r}")
            behaviors = tuple(b.strip() for b in
                              (row.get("expected_behaviors") or "").split(";") if b.strip())
            unknown = [b for b in behaviors if b not in BEHAVIORS]
            if unknown:
                raise ExpectationError(f"{path} row {n}: unknown behavior {unknown[0]!r}; "
                                       f"known: {', '.join(BEHAVIORS)}")
            rows.append(Expectation(sha, name, label, verdicts, behaviors,
                                    (row.get("notes") or "").strip()))
    return rows


class ExpectationIndex:
    def __init__(self, rows: list[Expectation]):
        self.by_sha = {r.sha256: r for r in rows if r.sha256}
        self.by_name = {r.name.lower(): r for r in rows if r.name and not r.sha256}
        self.used: set[int] = set()

    def find(self, sha256: str, name: str) -> Expectation | None:
        # Archive members keep their folder ("Lab_01/Lab_01-1.malware"); match the base name.
        base = name.replace("\\", "/").rsplit("/", 1)[-1].lower()
        hit = (self.by_sha.get(sha256.lower()) or self.by_name.get(name.lower())
               or self.by_name.get(base))
        if hit:
            self.used.add(id(hit))
        return hit

    def unused(self) -> list[Expectation]:
        rows = list(self.by_sha.values()) + list(self.by_name.values())
        return [r for r in rows if id(r) not in self.used]


# --- Running ----------------------------------------------------------------------------

@dataclass
class Result:
    file: str
    sample: str
    sha256: str
    kind: str
    label: str
    verdict: str
    confidence: str
    rule: str
    rules_matched: list[str]
    verdict_ok: bool | None
    expected_verdicts: tuple[str, ...]
    expected: tuple[str, ...]
    found: list[str]
    missed: list[str]
    surfaced: list[str]
    incomplete: list[str]
    seconds: float
    notes: str = ""


def iter_samples(root: Path, include: list[str] | None = None) -> Iterator[Path]:
    if root.is_file():
        yield root
        return
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink() \
                and (not include or any(path.match(p) for p in include)):
            yield path


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run_triage(path: Path, triage_args: list[str], keep: Path | None) -> dict[str, Any]:
    """One normal `unopened triage` run, JSON format, hunt queries off. Returns the report."""
    with tempfile.TemporaryDirectory(prefix="unopened-validate-") as tmp:
        out = keep if keep else Path(tmp)
        argv = ["triage", str(path), "--format", "json", "--out", str(out), "--no-hunt",
                *triage_args]
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = cli.main(argv)
        if code != cli.EXIT_OK:
            raise RuntimeError(stderr.getvalue().strip() or f"triage exited with {code}")
        return json.loads((out / f"{sha256_of(path)}.json").read_text(encoding="utf-8"))


def _nodes(report: dict[str, Any], name: str) -> Iterator[tuple[dict[str, Any], str]]:
    yield report, name
    for child in report.get("members", []):
        member = child.get("member", {})
        yield from _nodes(child["report"], (member.get("raw") or {}).get("name", "member"))


def _incomplete(report: dict[str, Any]) -> list[str]:
    out = []
    for node, _ in _nodes(report, ""):
        for name, a in node.get("analyzers", {}).items():
            if a.get("status") in INCOMPLETE:
                out.append(f"{name}:{a['status']}")
    return sorted(set(out))


def evaluate(file: str, report: dict[str, Any], sample: str, exp: Expectation | None,
             default_label: str, seconds: float) -> Result:
    ev = evidence_of(report)
    verdict = report["verdict"]
    surfaced = sorted(b for b, (_, test) in BEHAVIORS.items() if test(ev))
    expected = exp.behaviors if exp else ()
    found = [b for b in expected if b in surfaced]
    missed = [b for b in expected if b not in surfaced]
    verdict_ok = (verdict["value"] in exp.verdicts) if exp and exp.verdicts else None
    return Result(
        file=file, sample=sample, sha256=report["hashes"].get("sha256", ""),
        kind=(report.get("identification") or {}).get("kind", ""),
        label=exp.label if exp else default_label,
        verdict=verdict["value"], confidence=verdict["confidence"], rule=verdict["rule"],
        rules_matched=[r["rule"] for r in verdict.get("reasons", [])],
        verdict_ok=verdict_ok, expected_verdicts=exp.verdicts if exp else (),
        expected=expected, found=found, missed=missed, surfaced=surfaced,
        incomplete=_incomplete(report), seconds=seconds, notes=exp.notes if exp else "",
    )


def validate(samples: Path, index: ExpectationIndex, default_label: str,
             triage_args: list[str], keep: Path | None, include: list[str] | None = None,
             progress: Callable[[str], None] = lambda s: None) -> tuple[list[Result], list[str]]:
    results: list[Result] = []
    failures: list[str] = []
    for path in iter_samples(samples, include):
        rel = path.name if samples.is_file() else str(path.relative_to(samples))
        progress(rel)
        start = time.perf_counter()
        try:
            report = run_triage(path, triage_args, keep)
        except Exception as exc:  # noqa: BLE001 - one bad file must not stop the run
            failures.append(f"{rel}: {type(exc).__name__}: {exc}")
            continue
        seconds = time.perf_counter() - start
        matched = False
        for node, name in _nodes(report, path.name):
            exp = index.find(node["hashes"].get("sha256", ""), name)
            if exp:
                matched = True
                results.append(evaluate(rel, node, name, exp, default_label, seconds))
        if not matched:
            results.append(evaluate(rel, report, path.name, None, default_label, seconds))
    return results, failures


# --- Output -----------------------------------------------------------------------------

CSV_FIELDS = ["file", "sample", "sha256", "kind", "label", "verdict", "confidence", "rule",
              "rules_matched", "expected_verdict", "verdict_ok", "expected_behaviors",
              "found", "missed", "surfaced", "incomplete", "seconds", "notes"]


def write_csv(results: list[Result], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(CSV_FIELDS)
        for r in results:
            w.writerow([r.file, r.sample, r.sha256, r.kind, r.label, r.verdict, r.confidence,
                        r.rule, ";".join(r.rules_matched), "|".join(r.expected_verdicts),
                        "" if r.verdict_ok is None else str(r.verdict_ok).lower(),
                        ";".join(r.expected), ";".join(r.found), ";".join(r.missed),
                        ";".join(r.surfaced), ";".join(r.incomplete), f"{r.seconds:.2f}",
                        r.notes])


def _md(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def summary(results: list[Result], failures: list[str], unused: list[Expectation],
            triage_args: list[str]) -> str:
    lines = [
        "# Validation summary", "",
        f"unopened {__version__}. Triage options: "
        f"`{' '.join(triage_args) or '(defaults)'}`. Static analysis only.", "",
        "## Verdicts by label", "",
        "| Label | Files | " + " | ".join(VERDICTS) + " |",
        "|---|---|" + "---|" * len(VERDICTS),
    ]
    by_label: dict[str, Counter[str]] = {}
    for r in results:
        by_label.setdefault(r.label, Counter())[r.verdict] += 1
    for label, counts in sorted(by_label.items()):
        lines.append(f"| {label} | {sum(counts.values())} | "
                     + " | ".join(str(counts[v]) for v in VERDICTS) + " |")

    checked = [r for r in results if r.verdict_ok is not None]
    if checked:
        ok = sum(r.verdict_ok for r in checked)
        lines += ["", f"Expected verdict met on **{ok} of {len(checked)}** samples with an "
                  "expected verdict."]

    exp_rows = [r for r in results if r.expected]
    if exp_rows:
        lines += ["", "## Behavior coverage", "",
                  "How often each expected behavior was surfaced by the report.", "",
                  "| Behavior | Expected | Surfaced | Coverage |", "|---|---|---|---|"]
        for b, (title, _) in BEHAVIORS.items():
            n = sum(b in r.expected for r in exp_rows)
            if n:
                hit = sum(b in r.found for r in exp_rows)
                lines.append(f"| `{b}` {title} | {n} | {hit} | {hit / n:.0%} |")
        total = sum(len(r.expected) for r in exp_rows)
        hit = sum(len(r.found) for r in exp_rows)
        lines.append(f"| **All** | {total} | {hit} | {hit / total:.0%} |")

    misses = [r for r in results if r.missed or r.verdict_ok is False]
    if misses:
        lines += ["", "## Misses to explain", "",
                  "| Sample | Verdict | Expected | Missed behaviors | Incomplete checks | Notes |",
                  "|---|---|---|---|---|---|"]
        for r in misses:
            lines.append(f"| `{_md(r.sample)}` | {r.verdict} ({r.rule}) | "
                         f"{_md('|'.join(r.expected_verdicts)) or '-'} | "
                         f"{', '.join(r.missed) or '-'} | {', '.join(r.incomplete) or '-'} | "
                         f"{_md(r.notes)} |")

    benign = [r for r in results if r.label == "benign"]
    if benign:
        fps = [r for r in benign if r.verdict in ("malicious", "suspicious")]
        rate = len(fps) / len(benign)
        lines += ["", "## False positives on benign files", "",
                  f"{len(fps)} of {len(benign)} benign files ({rate:.1%}) were called "
                  "malicious or suspicious. Target: no malicious, suspicious under 5%."]
        if fps:
            rules = Counter(r.rule for r in fps)
            lines += ["", "| Rule | Files |", "|---|---|"]
            lines += [f"| {rule} | {n} |" for rule, n in rules.most_common()]
            lines += ["", "| File | Verdict | Rule | Rules matched |", "|---|---|---|---|"]
            lines += [f"| `{_md(r.file)}` | {r.verdict} | {r.rule} | "
                      f"{', '.join(r.rules_matched)} |" for r in fps]

    cna = [r for r in results if r.verdict == "could not analyze"]
    gaps = Counter(g for r in results for g in r.incomplete)
    if cna or gaps:
        lines += ["", "## Incomplete analysis", "",
                  f"{len(cna)} file(s) could not be analyzed. Checks that did not complete, "
                  "by analyzer and status:", "", "| Check | Files |", "|---|---|"]
        lines += [f"| {g} | {n} |" for g, n in gaps.most_common()]

    times = sorted({(r.file, r.seconds) for r in results})
    if times:
        secs = [t for _, t in times]
        lines += ["", "## Runtime", "",
                  "Per file triaged (an archive counts once, including its members).", "",
                  f"{len(secs)} file(s). Median {statistics.median(secs):.2f}s, "
                  f"slowest {max(secs):.2f}s, total {sum(secs):.1f}s."]

    if failures:
        lines += ["", "## Files that could not be triaged", ""]
        lines += [f"- `{_md(f)}`" for f in failures]
    if unused:
        lines += ["", "## Expectations with no matching sample", ""]
        lines += [f"- `{_md(e.sha256 or e.name)}`" for e in unused]
    return "\n".join(lines) + "\n"


# --- CLI --------------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="validate",
        description="Run unopened over a sample directory and compare with expectations. "
                    "Real samples belong only in an isolated analysis VM.",
        epilog="Anything after -- is passed to `unopened triage` (for example "
               "-- --capa-rules ~/rules/capa --yara-rules ~/rules/yara).",
    )
    p.add_argument("samples", type=Path, help="sample file or directory (searched recursively)")
    p.add_argument("--expectations", type=Path, help="expectations CSV")
    p.add_argument("--label", choices=["malicious", "benign", "unknown"], default="unknown",
                   help="label for files with no expectation row (default: unknown)")
    p.add_argument("--out", type=Path, default=Path("validation-results"),
                   help="directory for results.csv and summary.md "
                        "(default: ./validation-results)")
    p.add_argument("--keep-reports", action="store_true",
                   help="also keep each JSON report in OUT/reports (JSON reports contain raw "
                        "indicator values under 'raw' keys)")
    p.add_argument("--include", action="append", metavar="GLOB",
                   help="only triage files whose name matches GLOB (for example '*.zip'); "
                        "repeatable; default: every file")
    p.add_argument("--list-behaviors", action="store_true",
                   help="print the behavior labels usable in the expectations CSV and exit")
    return p


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    triage_args: list[str] = []
    if "--" in argv:
        cut = argv.index("--")
        argv, triage_args = argv[:cut], argv[cut + 1:]
    if any(a.split("=")[0] in RESERVED_TRIAGE_ARGS for a in triage_args):
        print("validate: error: --format, --out and --reputation are set by the harness "
              "(reputation lookups are never part of validation)", file=sys.stderr)
        return 2
    if "--list-behaviors" in argv:
        for b, (title, _) in BEHAVIORS.items():
            print(f"{b:20} {title}")
        return 0
    args = build_parser().parse_args(argv)
    if not args.samples.exists():
        print(f"validate: error: {args.samples} does not exist", file=sys.stderr)
        return 2
    try:
        rows = load_expectations(args.expectations) if args.expectations else []
    except (OSError, ExpectationError) as exc:
        print(f"validate: error: {exc}", file=sys.stderr)
        return 2

    args.out.mkdir(parents=True, exist_ok=True)
    keep = args.out / "reports" if args.keep_reports else None
    if keep:
        keep.mkdir(exist_ok=True)
    index = ExpectationIndex(rows)
    results, failures = validate(
        args.samples, index, args.label, triage_args, keep, include=args.include,
        progress=lambda name: print(f"triage {name}", file=sys.stderr))
    write_csv(results, args.out / "results.csv")
    (args.out / "summary.md").write_text(
        summary(results, failures, index.unused(), triage_args), encoding="utf-8")
    print(f"wrote {args.out / 'results.csv'} and {args.out / 'summary.md'} "
          f"({len(results)} result(s), {len(failures)} failure(s))", file=sys.stderr)
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
