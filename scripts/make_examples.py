"""Regenerate the example reports in examples/ from the synthetic test fixtures.

    python scripts/make_examples.py

Only reports are written; the inputs are built in a temporary folder and deleted. They are
the same harmless fixtures the tests use (reserved domains, a shortcut whose "payload" is
Write-Host fixture, a macro that shows a MsgBox, a page that smuggles a program whose
only instruction is `ret`).
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

from fixtures import lnk, mail, office, web  # noqa: E402

from unopened import pipeline  # noqa: E402
from unopened.analyzers import Options  # noqa: E402
from unopened.report import html, markdown  # noqa: E402

EXAMPLES = [
    ("phishing-email", "Action required.eml", mail.phish_eml, ("md", "html")),
    ("shortcut", "Invoice.pdf.lnk", lnk.encoded_powershell, ("md",)),
    ("macro-document", "Q3 report.doc", office.legacy_doc, ("md",)),
    ("html-smuggling", "Invoice.html", web.smuggling_html_exe, ("md",)),
]


def main() -> None:
    out = ROOT / "examples"
    out.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        for stem, name, make, formats in EXAMPLES:
            path = Path(tmp) / name
            path.write_bytes(make())
            report = pipeline.triage(path, Options())
            if "md" in formats:
                (out / f"{stem}.md").write_text(markdown.render(report), encoding="utf-8")
            if "html" in formats:
                (out / f"{stem}.html").write_text(html.render(report), encoding="utf-8")
            print(f"{stem}: {report.verdict['value']} ({report.verdict['rule']})")


if __name__ == "__main__":
    main()
