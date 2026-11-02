"""Regenerate docs/images/report-email.png from examples/phishing-email.html.

    python scripts/make_examples.py && python scripts/screenshot.py

Needs Playwright (`pip install playwright && playwright install chromium`).

Uses Playwright's Chromium on the generated *report* (never on a sample). The report has
no scripts and its Content-Security-Policy blocks network loads.
"""

from __future__ import annotations

from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    page_path = ROOT / "examples" / "phishing-email.html"
    out = ROOT / "docs" / "images" / "report-email.png"
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1000, "height": 900}, device_scale_factor=2)
        page.goto(page_path.as_uri())
        # Fold the verdict section so the key findings show above the fold.
        page.evaluate("""() => { for (const d of document.querySelectorAll('details.section'))
            if (d.querySelector('summary').textContent.trim() === 'Verdict') d.open = false; }""")
        page.wait_for_timeout(400)  # let the fold animation finish
        page.screenshot(path=str(out), clip={"x": 0, "y": 0, "width": 1000, "height": 900})
        browser.close()
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
