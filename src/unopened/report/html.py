"""Self-contained HTML report, for reading in a browser or sharing on a screen.

Built from the Markdown report, so both say exactly the same thing and the HTML inherits
its defanging: no indicator becomes a live link. The page has no scripts, loads nothing
from the network (a Content-Security-Policy forbids it), and escapes every value from the
sample. Only the small Markdown subset the report writer produces is converted: headings,
tables, lists, fenced code, bold, italics, code spans and the report's own
<details>/<summary> blocks.
"""

from __future__ import annotations

import html
import re
from typing import Any

from ..model import Report
from . import markdown

VERDICT_CLASS = {"malicious": "mal", "suspicious": "sus", "could not analyze": "cna",
                 "no findings": "nf"}
# Sections shown folded: long and mostly for pivoting or troubleshooting.
FOLDED = {"Indicators", "Hunt queries", "Analyzer status", "Hashes", "Not checked",
          "File identity"}
FENCE = re.compile(r"^(~{3,}|`{3,})(.*)$")
HEADING = re.compile(r"^(#{1,6})\s+(.*)$")
LIST_ITEM = re.compile(r"^(\s*)-\s+(.*)$")
DETAILS_OPEN = re.compile(r"^<details><summary>(.*)</summary>$")

CSS = """
:root { --bg:#ffffff; --fg:#1d232b; --muted:#5b6672; --line:#d9dee4; --panel:#f5f7f9;
  --code:#eef1f4; --mal:#b42318; --sus:#b54708; --cna:#475467; --nf:#067647; }
@media (prefers-color-scheme: dark) { :root { --bg:#14181d; --fg:#e4e8ec; --muted:#9aa5b1;
  --line:#2c333b; --panel:#1b2026; --code:#222830; --mal:#f97066; --sus:#fdb022;
  --cna:#98a2b3; --nf:#47cd89; } }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--fg);
  font:15px/1.55 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
main { max-width:1100px; margin:0 auto; padding:24px 16px 64px; }
h1 { font-size:22px; margin:0 0 4px; word-break:break-all; }
h2 { font-size:17px; margin:0; display:inline; }
h3, h4 { font-size:15px; margin:20px 0 8px; }
.banner { border-left:6px solid var(--accent); background:var(--panel); padding:14px 18px;
  border-radius:6px; margin:16px 0 20px; }
.banner .v { font-size:20px; font-weight:700; color:var(--accent); letter-spacing:.02em; }
.mal { --accent:var(--mal); } .sus { --accent:var(--sus); } .cna { --accent:var(--cna); }
.nf { --accent:var(--nf); }
details.section { border-top:1px solid var(--line); padding:12px 0; }
details.section > summary { cursor:pointer; list-style:none; }
details.section > summary::before { content:"\\25B8"; color:var(--muted); margin-right:8px;
  display:inline-block; transition:transform .15s; }
details.section[open] > summary::before { transform:rotate(90deg); }
details.section > summary::-webkit-details-marker { display:none; }
.body { margin-top:10px; }
table { border-collapse:collapse; width:100%; margin:8px 0 14px; display:block;
  overflow-x:auto; }
th, td { text-align:left; vertical-align:top; padding:6px 10px; border-bottom:1px solid
  var(--line); }
th { color:var(--muted); font-weight:600; }
code { background:var(--code); padding:1px 5px; border-radius:4px; font-size:13px;
  font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  word-break:break-all; }
pre { background:var(--code); padding:12px; border-radius:6px; overflow-x:auto;
  font-size:13px; }
pre code { background:none; padding:0; word-break:normal; white-space:pre; }
blockquote { margin:0 0 12px; color:var(--muted); }
ul { padding-left:22px; } li { margin:3px 0; }
.sev-high { color:var(--mal); font-weight:700; } .sev-medium { color:var(--sus);
  font-weight:700; } .sev-low, .sev-info { color:var(--muted); font-weight:700; }
details.inner { margin:8px 0; } details.inner > summary { cursor:pointer;
  color:var(--muted); }
footer { color:var(--muted); font-size:13px; margin-top:32px; }
"""


def render(report: Report) -> str:
    md = markdown.render(report)
    verdict = report.verdict or {}
    cls = VERDICT_CLASS.get(verdict.get("value", ""), "cna")
    body = convert(md)
    banner = (
        f'<div class="banner {cls}"><div class="v">{html.escape(verdict.get("value", "").upper())}'
        f'</div><div>{html.escape(verdict.get("confidence", ""))} confidence, rule '
        f'{html.escape(verdict.get("rule", ""))}</div></div>'
    )
    # The banner goes right after the title.
    body = body.replace("</h1>", "</h1>" + banner, 1)
    title = f"unopened: {report.file_name}"
    return (
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; "
        "style-src 'unsafe-inline'\">"
        "<meta name=\"referrer\" content=\"no-referrer\">"
        f"<title>{html.escape(title)}</title><style>{CSS}</style></head>"
        f"<body><main>{body}<footer>Static analysis only. Indicators are defanged and "
        "nothing on this page loads from the network.</footer></main></body></html>\n"
    )


def convert(md: str) -> str:
    """Convert the report's Markdown subset to HTML, folding each level-2 section."""
    out: list[str] = []
    lines = md.split("\n")
    i = 0
    open_section = False
    para: list[str] = []

    def flush_para() -> None:
        if para:
            out.append("<p>" + " ".join(inline(p) for p in para) + "</p>")
            para.clear()

    while i < len(lines):
        line = lines[i]
        fence = FENCE.match(line)
        if fence:
            flush_para()
            marker = fence.group(1)
            j = i + 1
            block = []
            while j < len(lines) and lines[j].strip() != marker:
                block.append(lines[j])
                j += 1
            out.append("<pre><code>" + html.escape("\n".join(block)) + "</code></pre>")
            i = j + 1
            continue
        head = HEADING.match(line)
        if head:
            flush_para()
            level, text = len(head.group(1)), head.group(2)
            if level == 2:
                if open_section:
                    out.append("</div></details>")
                plain = re.sub(r"\\(.)", r"\1", text)
                state = "" if plain in FOLDED else " open"
                out.append(f'<details class="section"{state}><summary><h2>{inline(text)}'
                           '</h2></summary><div class="body">')
                open_section = True
            else:
                out.append(f"<h{level}>{inline(text)}</h{level}>")
            i += 1
            continue
        details = DETAILS_OPEN.match(line)
        if details:
            flush_para()
            out.append(f'<details class="inner"><summary>{inline(details.group(1))}</summary>')
            i += 1
            continue
        if line.strip() == "</details>":
            flush_para()
            out.append("</details>")
            i += 1
            continue
        if line.startswith("|") and i + 1 < len(lines) and re.match(r"^\|(-{3}\|)+$",
                                                                    lines[i + 1]):
            flush_para()
            j = i + 2
            rows = []
            while j < len(lines) and lines[j].startswith("|"):
                rows.append(cells(lines[j]))
                j += 1
            headers = cells(line)
            thead = ("" if not any(h.strip() for h in headers) else
                     "<thead><tr>" + "".join(f"<th>{inline(h)}</th>" for h in headers)
                     + "</tr></thead>")
            tbody = "".join("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in row) + "</tr>"
                            for row in rows)
            out.append(f"<table>{thead}<tbody>{tbody}</tbody></table>")
            i = j
            continue
        if LIST_ITEM.match(line):
            flush_para()
            j, html_list = parse_list(lines, i)
            out.append(html_list)
            i = j
            continue
        if line.startswith("> "):
            flush_para()
            out.append(f"<blockquote>{inline(line[2:])}</blockquote>")
            i += 1
            continue
        if not line.strip():
            flush_para()
        else:
            para.append(line)
        i += 1
    flush_para()
    if open_section:
        out.append("</div></details>")
    return "\n".join(out)


def parse_list(lines: list[str], start: int) -> tuple[int, str]:
    """A bulleted list, nested by indentation."""
    out: list[str] = []
    stack: list[int] = []
    i = start
    while i < len(lines):
        m = LIST_ITEM.match(lines[i])
        if not m:
            break
        indent = len(m.group(1))
        if not stack or indent > stack[-1]:
            out.append("<ul>")
            stack.append(indent)
        else:
            while stack and indent < stack[-1]:
                out.append("</li></ul>")
                stack.pop()
            out.append("</li>")
        out.append("<li>" + severity(inline(m.group(2))))
        i += 1
    while stack:
        out.append("</li></ul>")
        stack.pop()
    return i, "".join(out)


def severity(text: str) -> str:
    return re.sub(r"\[(HIGH|MEDIUM|LOW|INFO)\]",
                  lambda m: f'<span class="sev-{m.group(1).lower()}">[{m.group(1)}]</span>',
                  text, count=1)


def cells(line: str) -> list[str]:
    """Split a table row on pipes that are not escaped (code spans escape theirs)."""
    inner = line.strip()[1:-1] if line.strip().endswith("|") else line.strip()[1:]
    parts, cur, k = [], [], 0
    while k < len(inner):
        ch = inner[k]
        if ch == "\\" and k + 1 < len(inner):
            cur.append(inner[k:k + 2])
            k += 2
            continue
        if ch == "|":
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
        k += 1
    parts.append("".join(cur).strip())
    return parts


def inline(text: str) -> str:
    """Code spans, bold, italics and backslash escapes; everything else escaped."""
    out: list[str] = []
    bold = italic = False
    k = 0
    n = len(text)
    while k < n:
        ch = text[k]
        if ch == "`":
            run = len(text[k:]) - len(text[k:].lstrip("`"))
            fence = "`" * run
            end = text.find(fence, k + run)
            if end != -1:
                content = text[k + run:end]
                if content.startswith(" ") and content.endswith(" ") and content.strip():
                    content = content[1:-1]
                content = content.replace("\\|", "|")
                out.append(f"<code>{html.escape(content)}</code>")
                k = end + run
                continue
        if ch == "\\" and k + 1 < n and not text[k + 1].isalnum():
            out.append(html.escape(text[k + 1]))
            k += 2
            continue
        if text.startswith("**", k):
            out.append("</strong>" if bold else "<strong>")
            bold = not bold
            k += 2
            continue
        if ch == "_":
            before = text[k - 1] if k else " "
            after = text[k + 1] if k + 1 < n else " "
            if not italic and not before.isalnum() and not after.isspace():
                out.append("<em>")
                italic = True
                k += 1
                continue
            if italic and not after.isalnum():
                out.append("</em>")
                italic = False
                k += 1
                continue
        out.append(html.escape(ch))
        k += 1
    if italic:
        out.append("</em>")
    if bold:
        out.append("</strong>")
    return "".join(out)


def summary_html(rows: list[dict[str, Any]], title: str) -> str:
    """Batch summary page: one row per file, worst verdict first."""
    body = [f"<h1>{html.escape(title)}</h1>", "<table><thead><tr><th>File</th><th>Type</th>"
            "<th>Verdict</th><th>Top reason</th><th>Report</th></tr></thead><tbody>"]
    for r in rows:
        cls = VERDICT_CLASS.get(r["verdict"], "cna")
        body.append(
            f"<tr><td><code>{html.escape(r['file'])}</code></td><td>{html.escape(r['type'])}"
            f'</td><td class="{cls}"><strong style="color:var(--accent)">'
            f"{html.escape(r['verdict'].upper())}</strong> ({html.escape(r['confidence'])}, "
            f"{html.escape(r['rule'])})</td><td>{html.escape(r['reason'])}</td>"
            f"<td><code>{html.escape(r['report'])}</code></td></tr>")
    body.append("</tbody></table>")
    return (
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; "
        "style-src 'unsafe-inline'\">"
        f"<title>{html.escape(title)}</title><style>{CSS}</style></head><body><main>"
        + "".join(body) + "</main></body></html>\n"
    )
