"""Markdown triage report, ready to paste into a ticket.

All indicators are defanged. As a final safety net the whole rendered document passes
through defang_text(), so nothing that slips into free text (file names, PDB paths,
parser messages) can become a live link.
"""

from __future__ import annotations

import re
from typing import Any

from ..hunt import display_queries
from ..indicators.defang import defang, defang_text
from ..model import INCOMPLETE_STATUSES, Report, Severity, Status

TYPE_TITLES = {
    "url": "URLs", "domain": "Domains", "ipv4": "IPv4 addresses", "ipv6": "IPv6 addresses",
    "email": "Email addresses", "hostname": "Host names", "mac_address": "MAC addresses",
    "unc_path": "Network (UNC) paths", "file_path": "File paths",
    "registry_key": "Registry keys",
}
SEVERITY_LABEL = {
    Severity.HIGH: "HIGH", Severity.MEDIUM: "MEDIUM", Severity.LOW: "LOW", Severity.INFO: "INFO",
}
STATUS_LABEL = {
    Status.OK: "ran", Status.PARTIAL: "PARTIAL", Status.ERROR: "FAILED",
    Status.TIMEOUT: "TIMED OUT", Status.UNAVAILABLE: "UNAVAILABLE",
    Status.NOT_APPLICABLE: "not applicable",
}
MAX_ROWS_PER_TYPE = 200
MAX_IMPORTS_SHOWN = 60


def code(value: Any) -> str:
    """Inline code span that survives backticks and table pipes."""
    text = str(value).replace("\r", " ").replace("\n", " ")
    text = text.replace("|", "\\|")
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if text.startswith("`") or text.endswith("`") or not text.strip() else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def esc(value: Any) -> str:
    """Escape free text for use in Markdown (including table cells)."""
    text = str(value).replace("\r", " ").replace("\n", " ")
    return re.sub(r"([\\`*_{}\[\]<>|#])", r"\\\1", text)


def table(headers: list[str], rows: list[list[str]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    lines += ["| " + " | ".join(row) + " |" for row in rows]
    return lines + [""]


def render(report: Report) -> str:
    lines: list[str] = []
    ft = report.file_type
    lines += [
        f"# Triage report: {code(report.file_name)}",
        "",
        "> Static analysis only. Nothing in this report came from running, opening or "
        "rendering the file.",
        "",
    ]
    incomplete = [r for r in report.results if r.status in INCOMPLETE_STATUSES]
    v = report.verdict
    summary = [
        ["Verdict", f"**{esc(v['value']).upper()}** ({esc(v['confidence'])} confidence, "
                    f"rule {esc(v['rule'])})"],
        ["File type", esc(ft.description) if ft else "unknown"],
        ["Size", f"{report.file_size:,} bytes"],
        ["SHA256", code(report.hashes.get("sha256", "not computed"))],
        ["Checks incomplete",
         str(len(incomplete)) + (" (see warnings below)" if incomplete else "")],
        ["Generated", f"{esc(report.generated_at)} by unopened {esc(report.tool_version)}"],
    ]
    lines += table(["", ""], summary)

    if incomplete:
        lines += ["## Warning: some checks did not complete", ""]
        for r in incomplete:
            lines.append(f"- **{r.name}**: {STATUS_LABEL[r.status]}. {esc(r.message)}")
            lines += [f"  - {esc(e)}" for e in r.errors]
        lines += ["", "A check that did not complete is not a clean result.", ""]

    lines += _verdict(report)
    lines += _findings(report)
    lines += _identity(report)
    lines += _hashes(report)
    if (pe := report.result("pe")) and pe.status in (Status.OK, Status.PARTIAL):
        lines += _pe(pe.data, report)
    lines += _section(report, "capa", "Capabilities (capa)", _capa)
    lines += _section(report, "office", "Office document", _office)
    lines += _section(report, "lnk", "Shortcut (LNK)", _lnk)
    lines += _section(report, "script", "Script", _script)
    lines += _section(report, "pdf", "PDF", _pdf)
    lines += _section(report, "archive", "Archive contents", _archive)
    lines += _section(report, "yara", "YARA", _yara)
    lines += _reputation(report)
    if report.children:
        lines += ["## Members", "",
                  "Each extracted member was triaged on its own. Their indicators are merged "
                  "into the Indicators section below.", ""]
        for child in report.children:
            lines += _member(child, level=3)
    lines += _indicators(report)
    # The hunt section defangs its own values: the document-wide pass would also rewrite
    # query syntax such as the ECS field file.name.
    tail = _status(report) + ["## Not checked", ""]
    tail += [f"- **{esc(n.check)}**: {esc(n.reason)}" for n in report.not_checked]
    tail.append("")
    return "\n".join([defang_text("\n".join(lines)), *_hunt(report),
                      defang_text("\n".join(tail))])


def _verdict(report: Report) -> list[str]:
    v = report.verdict
    lines = ["## Verdict", "",
             f"**{esc(v['value']).upper()}**, {esc(v['confidence'])} confidence.", ""]
    for r in v["reasons"]:
        lines.append(f"- **{esc(r['rule'])}** ({esc(r['verdict'])}): {esc(r['description'])}")
        lines += [f"  - {esc(e)}" for e in r["evidence"]]
    lines += [f"- {esc(c)}" for c in v.get("caveats", [])]
    lines += ["", f"_{esc(v['note'])}_", ""]
    return lines


def _member(child: dict[str, Any], level: int) -> list[str]:
    r: Report = child["report"]
    m = child["member"]
    h = "#" * min(level, 6)
    v = r.verdict
    lines = [f"{h} Member: {code(m['name'])}", ""]
    rows = [
        ["Verdict", f"**{esc(v['value']).upper()}** ({esc(v['confidence'])}, {esc(v['rule'])})"],
        ["Type", esc(r.file_type.description) if r.file_type else "unknown"],
        ["Size", f"{r.file_size:,} bytes"],
        ["SHA256", code(r.hashes.get("sha256", "not computed"))],
    ]
    if m.get("hidden"):
        rows.append(["Hidden", "yes"])
    if m.get("flags"):
        rows.append(["Name flags", esc(", ".join(m["flags"]))])
    if r.reputation is not None:
        rows.append(["Reputation", _reputation_summary(r.reputation)])
    lines += table(["", ""], rows)
    findings = [f for f in r.findings() if f.severity != Severity.INFO]
    if findings:
        lines += [f"- **[{SEVERITY_LABEL[f.severity]}] {esc(f.title)}**: {esc(f.detail)}"
                  for f in findings[:20]]
        if len(findings) > 20:
            lines.append(f"- ...and {len(findings) - 20} more in the JSON report")
        lines.append("")
    incomplete = [x for x in r.results if x.status in INCOMPLETE_STATUSES]
    if incomplete:
        lines += ["Not fully checked: " + "; ".join(
            f"{x.name} {STATUS_LABEL[x.status]}" for x in incomplete), ""]
    for sub in r.children:
        lines += _member(sub, level + 1)
    return lines


def _findings(report: Report) -> list[str]:
    findings = report.findings()
    lines = ["## Key findings", ""]
    if not findings:
        return lines + ["No findings from the checks that ran.", ""]
    for f in findings:
        detail = f": {esc(f.detail)}" if f.detail else ""
        lines.append(f"- **[{SEVERITY_LABEL[f.severity]}] {esc(f.title)}**{detail}")
    return lines + [""]


def _identity(report: Report) -> list[str]:
    ft = report.file_type
    lines = ["## File identity", ""]
    if ft is None:
        return lines + ["Type identification did not run.", ""]
    rows = [
        ["Name", code(report.file_name)],
        ["Identified as (from content)", esc(ft.description)],
    ]
    if ft.subtype:
        rows.append(["Subtype", esc(ft.subtype)])
    lines += table(["", ""], rows)
    if ft.mismatches:
        lines += ["**Name/content mismatches:**", ""]
        lines += [f"- [{SEVERITY_LABEL[m.severity]}] {esc(m.message)}" for m in ft.mismatches]
        lines.append("")
    return lines


def _hashes(report: Report) -> list[str]:
    names = {"md5": "MD5", "sha1": "SHA1", "sha256": "SHA256", "imphash": "Imphash", "tlsh": "TLSH"}
    rows = [[label, code(report.hashes[k])] for k, label in names.items() if k in report.hashes]
    if not rows:
        return ["## Hashes", "", "Hashes were not computed (see warnings).", ""]
    return ["## Hashes", ""] + table(["Hash", "Value"], rows)


def _pe(data: dict[str, Any], report: Report) -> list[str]:
    lines = ["## PE analysis", ""]
    h = data.get("headers")
    if h:
        rows = [
            ["Format", f"{esc(h['format'])} {'DLL' if h['is_dll'] else 'executable'}"],
            ["Architecture", esc(h["machine"])],
            ["Subsystem", esc(h["subsystem"])],
            ["Compile time (UTC)", esc(h["compile_time_utc"] or "zeroed")],
            ["Entry point", f"{code(h['entry_point_rva'])} in section "
                            f"{code(data.get('entry_point_section') or 'none')}"],
            [".NET assembly", "yes" if h["is_dotnet"] else "no"],
        ]
        if data.get("pdb_path"):
            rows.append(["Debug (PDB) path", code(data["pdb_path"])])
        if "overlay" in data:
            ov = data["overlay"]
            rows.append(["Overlay", f"{ov['size']:,} bytes at offset {ov['offset']:,}, "
                                    f"entropy {ov['entropy']:.2f}"])
        lines += table(["Field", "Value"], rows)

    lines += _signature(report)

    if data.get("sections"):
        lines += ["### Sections", ""]
        rows = [
            [code(s["name"]), code(s["virtual_address"]), f"{s['virtual_size']:,}",
             f"{s['raw_size']:,}", f"{s['entropy']:.2f}", code(s["permissions"])]
            for s in data["sections"]
        ]
        lines += table(["Name", "Virtual address", "Virtual size", "Raw size", "Entropy", "Perms"],
                       rows)
        lines += ["Entropy runs from 0 to 8. Above about 7.2 usually means compressed or "
                  "encrypted data.", ""]

    if "imports" in data:
        lines += ["### Imports", ""]
        interest = data.get("imports_of_interest", {})
        if interest:
            lines.append("Functions of interest, by what they allow a program to do "
                         "(legitimate software uses many of these too):")
            lines.append("")
            from ..analyzers.pe import import_categories

            cats = import_categories()
            for key, funcs in interest.items():
                shown = ", ".join(code(f) for f in funcs)
                lines.append(f"- **{esc(cats[key]['title'])}**: {shown}")
            lines.append("")
        lines.append(f"{data.get('import_count', 0)} imported function(s) from "
                     f"{len(data['imports'])} DLL(s).")
        lines.append("")
        if data["imports"]:
            lines += ["<details><summary>All imports</summary>", ""]
            for dll, funcs in data["imports"].items():
                shown = ", ".join(code(f) for f in funcs[:MAX_IMPORTS_SHOWN])
                extra = len(funcs) - MAX_IMPORTS_SHOWN
                more = f" and {extra} more" if extra > 0 else ""
                lines.append(f"- {code(dll)}: {shown}{more}")
            lines += ["", "</details>", ""]
    if data.get("exports"):
        names = data["exports"]
        lines += [f"### Exports ({data.get('export_count', len(names))})", ""]
        lines.append(", ".join(code(n) for n in names[:MAX_IMPORTS_SHOWN])
                     + (" ..." if len(names) > MAX_IMPORTS_SHOWN else ""))
        lines.append("")
    return lines


def _signature(report: Report) -> list[str]:
    sig = report.result("authenticode")
    lines = ["### Digital signature", ""]
    if sig is None or sig.status == Status.NOT_APPLICABLE:
        return []
    if sig.status not in (Status.OK, Status.PARTIAL):
        pe = report.result("pe")
        present = pe.data.get("signature_directory", {}).get("present") if pe else None
        state = {True: "present", False: "absent", None: "unknown"}[present]
        return lines + [f"Signature validity was **not checked** ({STATUS_LABEL[sig.status]}: "
                        f"{esc(sig.message)}). Signature data in the file: {state}.", ""]
    d = sig.data
    if not d["signed"]:
        return lines + ["Not signed.", ""]
    verdict = "**valid**" if d["valid"] else f"**INVALID** ({esc(d['result'])})"
    lines += [f"Signature present, {verdict}. Checked offline against {esc(d['trust_store'])}; "
              "revocation not checked.", ""]
    if d.get("detail"):
        lines += [f"Verifier detail: {esc(d['detail'])}", ""]
    for s in d.get("signers", []):
        lines.append(f"- Signer: {code(s.get('subject') or 'unknown')}, issuer "
                     f"{code(s.get('issuer') or 'unknown')}, timestamp "
                     f"{esc(s.get('timestamp') or 'none')}")
    return lines + [""]


def _indicators(report: Report) -> list[str]:
    lines = ["## Indicators", ""]
    strings = report.result("strings")
    if strings is None or strings.status not in (Status.OK, Status.PARTIAL):
        return lines + ["Indicator extraction did not run (see warnings).", ""]
    lines.append("Extracted from strings in the file and from what the analyzers decoded "
                 "(macro source, shortcut arguments). All network indicators are "
                 "defanged. Presence of an indicator is a lead to pivot on, not proof of "
                 "malicious behavior.")
    lines.append("")
    if not report.indicators:
        lines += ["No indicators found.", ""]
    by_type: dict[str, list[dict[str, Any]]] = {}
    for ind in report.indicators:
        by_type.setdefault(ind["type"], []).append(ind)
    for kind, items in by_type.items():
        lines += [f"### {TYPE_TITLES.get(kind, kind)} ({len(items)})", ""]
        rows = [
            [code(i["value"]), str(i["count"]),
             "" if i["first_offset"] is None else f"0x{i['first_offset']:x}",
             esc(", ".join(i.get("sources", []))), esc(", ".join(i["tags"]) or "")]
            for i in items[:MAX_ROWS_PER_TYPE]
        ]
        lines += table(["Value", "Seen", "First offset", "Found by", "Notes"], rows)
        if len(items) > MAX_ROWS_PER_TYPE:
            lines += [f"...and {len(items) - MAX_ROWS_PER_TYPE} more in the JSON report.", ""]
    if report.allowlisted_counts:
        hidden = ", ".join(f"{n} {TYPE_TITLES.get(k, k).lower()}"
                           for k, n in sorted(report.allowlisted_counts.items()))
        lines += [f"Hidden by the allowlist ({esc(strings.data.get('allowlist_source', ''))}): "
                  f"{hidden}. They are known-benign noise such as certificate-authority URLs.", ""]
    s = strings.data
    if "ascii_strings" in s:
        lines += [f"Strings examined: {s['ascii_strings']:,} ASCII and {s['utf16_strings']:,} "
                  f"UTF-16LE, minimum length {s['min_length']}"
                  + (" (stopped at the limit)" if s.get("truncated") else "") + ".", ""]
    return lines


def _status(report: Report) -> list[str]:
    rows = [
        [esc(r.name), STATUS_LABEL[r.status], f"{r.duration_seconds:.2f}s",
         esc(r.message or ("; ".join(r.errors)))]
        for r in report.results
    ]
    return ["## Analyzer status", ""] + table(["Analyzer", "Status", "Time", "Message"], rows)


def _section(report: Report, name: str, title: str, body) -> list[str]:
    r = report.result(name)
    if r is None or r.status == Status.NOT_APPLICABLE:
        return []
    lines = [f"## {title}", ""]
    if r.status not in (Status.OK, Status.PARTIAL):
        return lines + [f"**Not checked** ({STATUS_LABEL[r.status]}): {esc(r.message)}", ""]
    lines += body(r.data)
    if r.errors:
        lines += ["Parts that could not be read:", ""]
        lines += [f"- {esc(e)}" for e in r.errors] + [""]
    return lines


def _capa(d: dict[str, Any]) -> list[str]:
    caps = d.get("capabilities", [])
    lines = [f"{len(caps)} capabilit{'y' if len(caps) == 1 else 'ies'} from "
             f"{d.get('rule_count', 0):,} rules ({esc(d.get('backend', ''))} backend). "
             "capa infers these from code patterns; nothing was run.", ""]
    if not d.get("signatures"):
        lines += ["Library-function signatures were not configured, so code from statically "
                  "linked libraries may add matches.", ""]
    for lim in d.get("limitations", []):
        lines += [f"**Limited analysis:** {esc(lim['description'] or lim['rule'])}", ""]
    if caps:
        rows = [
            [esc(c["name"]), code(c["namespace"]),
             esc(", ".join(f"{a['id']} {a['technique']}".strip() for a in c["attack"])),
             esc(", ".join(c["mbc"])), str(c["matches"])]
            for c in caps
        ]
        lines += table(["Capability", "Namespace", "ATT&CK", "MBC", "Matches"], rows)
        techniques: dict[str, set[str]] = {}
        for c in caps:
            for a in c["attack"]:
                if a["id"]:
                    techniques.setdefault(a["tactic"], set()).add(a["id"])
        if techniques:
            lines += ["**ATT&CK summary:**", ""]
            lines += [f"- {esc(t)}: {', '.join(sorted(ids))}"
                      for t, ids in sorted(techniques.items())]
            lines.append("")
    return lines


def _office(d: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    if d.get("encrypted"):
        lines += ["**Encrypted:** contents could not be inspected.", ""]
    modules = d.get("modules", [])
    lines += [f"VBA macro modules: {len(modules)}. XLM (Excel 4.0) macros: "
              f"{'yes' if d.get('xlm_macros') else 'no'}.", ""]
    if d.get("autoexec"):
        lines += ["**Auto-run triggers:**", ""]
        lines += [f"- {code(a['keyword'])}: {esc(a['description'])}" for a in d["autoexec"]]
        lines.append("")
    if d.get("suspicious"):
        lines += ["**Suspicious keywords:**", ""]
        lines += [f"- {code(x['keyword'])}: {esc(x['description'])}" for x in d["suspicious"]]
        lines.append("")
    for m in modules:
        excerpt = m["source"][:1200]
        fence = "~~~~" if "~~~" in excerpt else "~~~"
        lines += [f"<details><summary>Macro source: {esc(m['name'])} ({m['lines']} lines, "
                  f"from {esc(m['stream'])})</summary>", "", f"{fence}vb", excerpt, fence, "",
                  "</details>", ""]
    if d.get("xlm_excerpt"):
        lines += ["<details><summary>XLM macro records</summary>", "", "~~~"]
        lines += d["xlm_excerpt"][:50]
        lines += ["~~~", "", "</details>", ""]
    rels = d.get("external_relationships", [])
    if rels:
        lines += ["**External references:**", ""]
        lines += table(["Type", "Target", "Part"],
                       [[esc(r["type"]), code(r["target"]), code(r["part"])] for r in rels])
    for dde in d.get("dde", []):
        lines += [f"**DDE field** in {code(dde['part'])}: {code(dde['field'])}", ""]
    if d.get("embedded"):
        lines += ["**Embedded objects:**", ""]
        rows = [[esc(o["kind"]), code(o.get("filename") or ""), code(o["stream"]),
                 f"{o['size']:,}" if isinstance(o.get("size"), int) else ""]
                for o in d["embedded"]]
        lines += table(["Kind", "File name", "Location", "Size"], rows)
    return lines


def _lnk(d: dict[str, Any]) -> list[str]:
    s = d.get("shortcut", {})
    rows = [["Target", code(s.get("target") or "unknown")]]
    args = s.get("arguments_compact") or s.get("arguments")
    if args:
        label = "Arguments (whitespace collapsed)" if s.get("arguments_compact") else "Arguments"
        rows.append([label, code(args) + f" ({s.get('arguments_length', 0):,} chars)"])
    if s.get("decoded_command"):
        rows.append(["Decoded command (text only)", code(s["decoded_command"])])
    for key, label in [("working_directory", "Working directory"),
                       ("relative_path", "Relative path"), ("icon_location", "Icon"),
                       ("description", "Comment"), ("window_style", "Window"),
                       ("machine_id", "Creator machine (NetBIOS)"),
                       ("mac_address", "Creator MAC address")]:
        if s.get(key):
            rows.append([label, code(s[key])])
    if s.get("appended_bytes"):
        rows.append(["Appended data", f"{s['appended_bytes']:,} bytes after the shortcut"])
    return table(["Field", "Value"], rows)


def _yara(d: dict[str, Any]) -> list[str]:
    matches = d.get("matches", [])
    lines = [f"{d.get('rule_count', 0):,} rules from {d.get('rule_files_compiled', 0)} of "
             f"{d.get('rule_files', 0)} rule file(s); {len(matches)} matched.", ""]
    for m in matches:
        tags = f" (tags: {esc(', '.join(m['tags']))})" if m["tags"] else ""
        lines.append(f"- **{esc(m['rule'])}** in namespace {code(m['namespace'])}{tags}")
        if m["meta"].get("description"):
            lines.append(f"  - {esc(m['meta']['description'])}")
        for st in m["strings"]:
            shown = ", ".join(f"{code(i['data'])} at 0x{i['offset']:x}" for i in st["instances"])
            more = f" (+{st['count'] - len(st['instances'])} more)" \
                if st["count"] > len(st["instances"]) else ""
            lines.append(f"  - {code(st['identifier'])}: {shown}{more}")
    return lines + [""]


def _script(d: dict[str, Any]) -> list[str]:
    lines = [f"Language: {esc(d.get('language'))}. {d.get('lines', 0):,} lines, longest "
             f"{d.get('longest_line', 0):,} characters.", ""]
    if d.get("layers"):
        steps = ", ".join(f"{esc(x['technique'])} x{x['count']}" for x in d["layers"])
        lines += [f"Deobfuscation (text transformations only, nothing was run): {steps}.", ""]
    if d.get("keywords"):
        lines += table(["Keyword", "Severity", "Matched"],
                       [[esc(k["title"]), esc(k["severity"]), code(k["match"])]
                        for k in d["keywords"]])
    if d.get("deobfuscated"):
        text = d["deobfuscated"]
        fence = "~~~~" if "~~~" in text else "~~~"
        more = " (truncated)" if d.get("deobfuscated_truncated") else ""
        lines += [f"<details><summary>Deobfuscated text{more}</summary>", "", fence, text,
                  fence, "", "</details>", ""]
    return lines


def _pdf(d: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    kw = d.get("keywords", {})
    if kw:
        lines += ["Keyword counts (raw bytes, #xx escapes decoded): "
                  + ", ".join(f"{code(k)} {n}" for k, n in sorted(kw.items())), ""]
    for js in d.get("javascript", []):
        text = js.get("deobfuscated") or js["source"]
        label = "deobfuscated " if js.get("deobfuscated") else ""
        fence = "~~~~" if "~~~" in text else "~~~"
        lines += [f"<details><summary>JavaScript ({esc(js['trigger'])}, {js['length']:,} "
                  f"chars, {label}source)</summary>", "", fence + "js", text[:4000], fence, "",
                  "</details>", ""]
    for la in d.get("launch", []):
        lines += [f"- Launch: {code(la.get('windows_file') or la.get('target') or '')}"
                  + (f" parameters {code(la['parameters'])}" if la.get("parameters") else ""),
                  ""]
    if d.get("embedded"):
        lines += table(["Attachment", "Declared size"],
                       [[code(e["name"]), f"{e['declared_size']:,}" if e.get("declared_size")
                         is not None else ""] for e in d["embedded"]])
    return lines


def _archive(d: dict[str, Any]) -> list[str]:
    members = d.get("members", [])
    lines = [f"{esc(str(d.get('format', '')).upper())}: {d.get('member_count', len(members)):,} "
             f"member(s), {d.get('extracted_files', 0):,} extracted "
             f"({d.get('extracted_bytes', 0):,} bytes)."]
    if d.get("filesystem"):
        lines[-1] += f" File system: {esc(d['filesystem'])}."
    if d.get("password_used"):
        lines[-1] += f" Opened with password {code(d['password_used'])}."
    lines.append("")
    if d.get("stopped"):
        lines += [f"**Extraction stopped:** {esc(d['stopped'])}", ""]
    if members:
        rows = []
        for m in members[:MAX_ROWS_PER_TYPE]:
            notes = [esc(x) for x in m.get("flags", [])]
            if m.get("hidden"):
                notes.append("hidden")
            if m.get("encryption"):
                notes.append(esc(m["encryption"]))
            if m.get("skipped"):
                notes.append(esc(m["skipped"]))
            size = f"{m['size']:,}" if isinstance(m.get("size"), int) else ""
            rows.append([code(m["name"]), size, "; ".join(notes)])
        lines += table(["Member", "Size", "Notes"], rows)
        if len(members) > MAX_ROWS_PER_TYPE:
            lines += [f"...and {len(members) - MAX_ROWS_PER_TYPE} more in the JSON report.", ""]
    return lines


REP_NAMES = {"malwarebazaar": "MalwareBazaar", "virustotal": "VirusTotal"}


def _defang_value(kind: str, value: str) -> str:
    return defang_text(value) if kind == "text" else defang(kind, value)


def _reputation_summary(rep: dict[str, Any]) -> str:
    if rep.get("skipped"):
        return f"not looked up ({esc(rep['skipped'])})"
    parts = []
    for name, res in rep.get("sources", {}).items():
        label = REP_NAMES.get(name, name)
        if res["status"] == "found" and name == "virustotal":
            d = res["data"]
            parts.append(f"{label}: {d.get('malicious', 0)} malicious")
        elif res["status"] == "found":
            sig = res["data"].get("signature")
            parts.append(f"{label}: known" + (f" ({esc(sig)})" if sig else ""))
        else:
            parts.append(f"{label}: {esc(res['status'].replace('_', ' '))}")
    return "; ".join(parts) or "no sources"


def _reputation(report: Report) -> list[str]:
    rep = report.reputation
    if rep is None:
        return []
    lines = ["## Reputation", "",
             "Hash lookups (only the SHA256 was sent; the file was not uploaded). A hash "
             "that no source knows is unknown, not clean.", ""]
    if rep.get("skipped"):
        return lines + [f"Not looked up: {esc(rep['skipped'])}.", ""]
    rows = []
    for name, res in rep.get("sources", {}).items():
        d = res.get("data") or {}
        if res["status"] == "found" and name == "virustotal":
            detail = (f"{d.get('malicious', 0)} malicious, {d.get('suspicious', 0)} suspicious, "
                      f"{d.get('undetected', 0)} undetected")
            if d.get("threat_label"):
                detail += f"; label {code(d['threat_label'])}"
            if d.get("first_submission"):
                detail += f"; first submitted {esc(d['first_submission'])}"
        elif res["status"] == "found":
            bits = []
            if d.get("signature"):
                bits.append(f"family {code(d['signature'])}")
            if d.get("tags"):
                bits.append("tags " + ", ".join(code(t) for t in d["tags"][:10]))
            if d.get("first_seen"):
                bits.append(f"first seen {esc(d['first_seen'])}")
            detail = "; ".join(bits) or "known sample"
        else:
            detail = esc(res.get("detail", ""))
        rows.append([REP_NAMES.get(name, esc(name)),
                     esc(res["status"].replace("_", " ")), detail])
    return lines + table(["Source", "Result", "Details"], rows)


def _hunt(report: Report) -> list[str]:
    hunt = report.hunt
    if not hunt:
        return []
    lines = ["## Hunt queries", "",
             f"Searches for this file's hashes, names and network indicators over the last "
             f"{hunt['days']} days. Hash and file-name queries can be pasted as they are. "
             "Network values below are defanged like the rest of this report; the paste-ready "
             "versions are in the `.hunt.txt` file written with `--out`, and in the JSON "
             "report under `hunt.raw`.", ""]
    if hunt.get("truncated"):
        lines += ["Value lists were capped: " + esc("; ".join(hunt["truncated"])) + ".", ""]
    any_query = False
    for platform in display_queries(hunt, _defang_value).values():
        if not platform["queries"]:
            continue
        any_query = True
        lines += [f"### {esc(platform['title'])}", ""]
        for q in platform["queries"]:
            fence = "~~~~" if "~~~" in q["query"] else "~~~"
            lines += [f"**{esc(q['title'])}**" + (f" ({esc(q['note'])})" if q.get("note") else ""),
                      "", fence, q["query"], fence, ""]
    if not any_query:
        lines += ["No values to search for.", ""]
    return lines
