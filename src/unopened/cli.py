"""Command-line interface.

    unopened triage FILE [--format md|json|html|both|all] [--out DIR] [--allowlist PATH] ...
    unopened triage DIR --out OUT   (every file in DIR, plus summary.md / summary.html)

Exit codes: 0 report written (whatever it found), 2 usage or configuration error,
3 the input could not be read.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

from . import __version__
from .analyzers import Options
from .extraction import Limits
from .indicators.allowlist import Allowlist, AllowlistError
from .pipeline import triage
from .report import html as html_report
from .report import json_report, markdown

EXIT_OK, EXIT_USAGE, EXIT_INPUT = 0, 2, 3
DEFAULT_MAX_SIZE = 200 * 1024 * 1024
SIZE_UNITS = {"": 1, "b": 1, "k": 1024, "kb": 1024, "m": 1024**2, "mb": 1024**2,
              "g": 1024**3, "gb": 1024**3}


def parse_size(text: str) -> int:
    m = re.fullmatch(r"\s*(\d+)\s*([a-zA-Z]*)\s*", text)
    if not m or m.group(2).lower() not in SIZE_UNITS:
        raise argparse.ArgumentTypeError(f"invalid size {text!r} (examples: 5000000, 50MB, 1G)")
    return int(m.group(1)) * SIZE_UNITS[m.group(2).lower()]


def positive_int(text: str) -> int:
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return value


def positive_float(text: str) -> float:
    value = float(text)
    if value <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return value


def _env_path(name: str) -> Path | None:
    value = os.environ.get(name, "").strip()
    return Path(value).expanduser() if value else None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="unopened",
        description="Static triage of a suspicious file for SOC analysts. "
                    "The file is never executed, opened or rendered.",
    )
    parser.add_argument("--version", action="version", version=f"unopened {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    t = sub.add_parser("triage", help="analyze one file and write a report")
    t.add_argument("file", type=Path,
                   help="file to analyze, or a folder to analyze every file in it (needs --out)")
    t.add_argument("--format", choices=["md", "json", "html", "both", "all"], default="md",
                   help="report format: md, json, html, both (md and json) or all "
                        "(default: md)")
    t.add_argument("--out", type=Path,
                   help="directory to write <sha256>.md / <sha256>.json into; "
                        "without it the report goes to standard output")
    t.add_argument("--allowlist", type=Path,
                   help="TOML allowlist of known-benign indicators (default: built-in)")
    t.add_argument("--max-size", type=parse_size, default=DEFAULT_MAX_SIZE,
                   help="refuse files larger than this (default: 200MB)")
    t.add_argument("--timeout", type=positive_float, default=60.0,
                   help="seconds each analyzer may run before it is stopped (default: 60)")
    t.add_argument("--yara-rules", type=Path, default=_env_path("UNOPENED_YARA_RULES"),
                   help="YARA rules directory or file (default: $UNOPENED_YARA_RULES)")
    t.add_argument("--capa-rules", type=Path, default=_env_path("UNOPENED_CAPA_RULES"),
                   help="capa rules directory (default: $UNOPENED_CAPA_RULES)")
    t.add_argument("--capa-signatures", type=Path,
                   default=_env_path("UNOPENED_CAPA_SIGNATURES"),
                   help="capa FLIRT signatures directory, for library-function recognition "
                        "(default: $UNOPENED_CAPA_SIGNATURES)")
    t.add_argument("--capa-timeout", type=positive_float, default=300.0,
                   help="seconds capa may run before it is stopped (default: 300)")
    t.add_argument("--file-timeout", type=positive_float, default=900.0,
                   help="seconds for the whole file, archive members included; checks "
                        "still pending when it runs out are reported as not run "
                        "(default: 900)")
    t.add_argument("--reputation", action="store_true",
                   help="look up SHA256 hashes at MalwareBazaar (ABUSECH_API_KEY) and "
                        "VirusTotal (VT_API_KEY); off by default; never uploads the file")
    t.add_argument("--max-lookups", type=positive_int, default=20,
                   help="maximum hashes looked up per run, file plus members (default: 20)")
    t.add_argument("--hunt-days", type=positive_int, default=30,
                   help="time window for the SIEM hunt queries (default: 30)")
    t.add_argument("--no-hunt", action="store_true", help="do not generate SIEM hunt queries")
    t.add_argument("--archive-password", action="append", default=None, metavar="PASSWORD",
                   help="password to try on encrypted archives; repeatable "
                        "(default: infected)")
    t.add_argument("--max-depth", type=positive_int, default=3,
                   help="how deep to extract nested archives (default: 3)")
    t.add_argument("--max-files", type=positive_int, default=1000,
                   help="maximum members extracted in total (default: 1000)")
    t.add_argument("--max-total-size", type=parse_size, default=500 * 1024 * 1024,
                   help="maximum bytes extracted in total (default: 500MB)")
    t.add_argument("--max-ratio", type=positive_float, default=100.0,
                   help="maximum compression ratio per member (default: 100)")
    t.add_argument("--min-string-length", type=positive_int, default=5,
                   help="minimum printable run counted as a string (default: 5)")
    t.add_argument("--max-strings", type=positive_int, default=200_000,
                   help="stop examining strings after this many (default: 200000)")
    return parser


def error(message: str) -> None:
    print(f"unopened: error: {message}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.format in ("both", "all") and args.out is None:
        error(f"--format {args.format} needs --out DIR")
        return EXIT_USAGE

    path: Path = args.file
    if path.is_dir():
        if args.out is None:
            error("triaging a folder needs --out DIR")
            return EXIT_USAGE
        return _batch(args, path)
    try:
        st = path.stat()
    except OSError as exc:
        error(f"cannot read {path}: {exc.strerror or exc}")
        return EXIT_INPUT
    if not path.is_file():
        error(f"{path} is not a regular file")
        return EXIT_INPUT
    if st.st_size > args.max_size:
        error(f"{path} is {st.st_size:,} bytes, larger than --max-size ({args.max_size:,}); "
              "not analyzed")
        return EXIT_INPUT
    try:
        with path.open("rb") as f:
            f.read(1)
    except OSError as exc:
        error(f"cannot read {path}: {exc.strerror or exc}")
        return EXIT_INPUT

    options = _options(args)
    if options is None:
        return EXIT_USAGE
    report = triage(path, options)
    outputs = _render(report, args.format)
    if args.out is None:
        sys.stdout.write(outputs[0][1])
        return EXIT_OK
    try:
        _write(report, outputs, args.out)
    except OSError as exc:
        error(f"cannot write report: {exc}")
        return EXIT_USAGE
    return EXIT_OK


def _render(report, fmt: str) -> list[tuple[str, str]]:
    outputs = []
    if fmt in ("md", "both", "all"):
        outputs.append(("md", markdown.render(report)))
    if fmt in ("json", "both", "all"):
        outputs.append(("json", json_report.render(report)))
    if fmt in ("html", "all"):
        outputs.append(("html", html_report.render(report)))
    return outputs


def _write(report, outputs: list[tuple[str, str]], out: Path) -> str:
    """Write the report files; returns the stem (the file's SHA256)."""
    out.mkdir(parents=True, exist_ok=True)
    stem = report.hashes.get("sha256") or "report"
    if report.hunt:
        from .hunt import render_text

        outputs = outputs + [("hunt.txt", render_text(report.hunt, report.file_name))]
    for ext, text in outputs:
        target = out / f"{stem}.{ext}"
        target.write_text(text, encoding="utf-8")
        print(f"wrote {target}", file=sys.stderr)
    return stem


VERDICT_ORDER = {"malicious": 0, "suspicious": 1, "could not analyze": 2, "no findings": 3}


def _batch(args: argparse.Namespace, folder: Path) -> int:
    """Triage every regular file under `folder` (symbolic links are skipped), then write
    summary.md (and summary.html with --format html or all), worst verdict first."""
    from .indicators.defang import defang_text

    options = _options(args)
    if options is None:
        return EXIT_USAGE
    files = sorted(p for p in folder.rglob("*") if p.is_file() and not p.is_symlink())
    rows = []
    for path in files:
        rel = str(path.relative_to(folder))
        size = path.stat().st_size
        if size > args.max_size:
            rows.append({"file": rel, "type": "", "verdict": "could not analyze",
                         "confidence": "high", "rule": "--max-size",
                         "reason": f"{size:,} bytes, larger than --max-size", "report": ""})
            continue
        print(f"triaging {rel}", file=sys.stderr)
        report = triage(path, options)
        report.file_name = rel
        try:
            stem = _write(report, _render(report, args.format), args.out)
        except OSError as exc:
            error(f"cannot write report: {exc}")
            return EXIT_USAGE
        v = report.verdict
        reasons = next((r["evidence"] for r in v.get("reasons", []) if r["rule"] == v["rule"]),
                       [])
        ext = "html" if args.format == "html" else ("json" if args.format == "json" else "md")
        rows.append({
            "file": defang_text(rel), "type": report.file_type.description
            if report.file_type else "unknown",
            "verdict": v["value"], "confidence": v["confidence"], "rule": v["rule"],
            "reason": defang_text(str(reasons[0])) if reasons else "",
            "report": f"{stem}.{ext}",
        })
    rows.sort(key=lambda r: (VERDICT_ORDER.get(r["verdict"], 9), r["file"]))
    title = f"unopened summary: {len(rows)} file(s) in {folder.name}"
    lines = [f"# {title}", "", "| File | Type | Verdict | Top reason | Report |",
             "|---|---|---|---|---|"]
    for r in rows:
        lines.append("| " + " | ".join([
            markdown.code(r["file"]), markdown.esc(r["type"]),
            f"**{r['verdict'].upper()}** ({r['confidence']}, {markdown.esc(r['rule'])})",
            markdown.esc(r["reason"]), markdown.code(r["report"]) if r["report"] else "",
        ]) + " |")
    try:
        (args.out / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"wrote {args.out / 'summary.md'}", file=sys.stderr)
        if args.format in ("html", "all"):
            (args.out / "summary.html").write_text(html_report.summary_html(rows, title),
                                                   encoding="utf-8")
            print(f"wrote {args.out / 'summary.html'}", file=sys.stderr)
    except OSError as exc:
        error(f"cannot write summary: {exc}")
        return EXIT_USAGE
    return EXIT_OK


def _options(args: argparse.Namespace) -> Options | None:
    try:
        allowlist = Allowlist.load(args.allowlist)
    except AllowlistError as exc:
        error(str(exc))
        return None

    return Options(
        min_string_length=args.min_string_length,
        max_strings=args.max_strings,
        timeout=args.timeout,
        timeouts={"capa": args.capa_timeout},
        file_timeout=args.file_timeout,
        allowlist=allowlist,
        yara_rules=args.yara_rules,
        capa_rules=args.capa_rules,
        capa_signatures=args.capa_signatures,
        limits=Limits(max_depth=args.max_depth, max_files=args.max_files,
                      max_total_size=args.max_total_size, max_member_size=args.max_size,
                      max_ratio=args.max_ratio),
        archive_passwords=tuple(args.archive_password or ["infected"]),
        reputation=args.reputation,
        max_lookups=args.max_lookups,
        hunt=not args.no_hunt,
        hunt_days=args.hunt_days,
    )
