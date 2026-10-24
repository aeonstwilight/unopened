"""HTML report: same content as the Markdown report, self-contained, nothing live."""

from __future__ import annotations

import re

import pytest

from unopened import pipeline
from unopened.analyzers import Options
from unopened.report import html


@pytest.fixture
def phish_page(make_file, mail_fx):
    report = pipeline.triage(make_file("phish.eml", mail_fx.phish_eml()), Options(),
                             isolate=False)
    return html.render(report)


def test_page_is_self_contained(phish_page):
    assert "default-src 'none'" in phish_page
    assert "<script" not in phish_page.lower()
    assert not re.search(r"<(a|img|link|iframe|object|embed)\b", phish_page)
    assert not re.search(r"\b(?:src|href)=", phish_page)


def test_no_live_links(phish_page):
    assert "https://" not in phish_page and "http://" not in phish_page
    assert "hxxps://login.micros0ft-support.example[.]com" in phish_page


def test_verdict_banner_and_sections(phish_page):
    assert 'class="banner mal"' in phish_page
    assert "<h2>Email</h2>" in phish_page
    assert '<details class="section"><summary><h2>Indicators</h2>' in phish_page  # folded
    assert '<details class="section" open><summary><h2>Key findings</h2>' in phish_page
    assert '<span class="sev-high">[HIGH]</span>' in phish_page


@pytest.mark.parametrize("text,expected", [
    ("plain <b>tag</b>", "plain &lt;b&gt;tag&lt;/b&gt;"),
    ("`a\\|b`", "<code>a|b</code>"),
    ("**bold** and \\_not italic\\_", "<strong>bold</strong> and _not italic_"),
    ("``x ` y``", "<code>x ` y</code>"),
    ("_whole line in italics_", "<em>whole line in italics</em>"),
])
def test_inline(text, expected):
    assert html.inline(text) == expected


def test_hostile_markup_in_values_is_escaped():
    md = ("# Triage report: `<script>alert(1)</script>`\n\n| a | b |\n|---|---|\n"
          "| \\<img src=x\\> | `</td><script>` |\n\n~~~\n<iframe src=x>\n~~~\n")
    page = html.convert(md)
    assert "<script" not in page and "<img" not in page and "<iframe" not in page


def test_table_cells_keep_escaped_pipes():
    assert html.cells("| `a\\|b` | c |") == ["`a\\|b`", "c"]
