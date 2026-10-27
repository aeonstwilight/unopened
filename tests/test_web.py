"""HTML, SVG, HTA and WSF: smuggling, redirects, credential forms, scripts (M11)."""

from __future__ import annotations

import pytest

from unopened import pipeline
from unopened.analyzers import Options
from unopened.identify import identify
from unopened.report import html as html_report
from unopened.report import json_report, markdown


def triage(make_file, name, data):
    return pipeline.triage(make_file(name, data), Options(hunt=False))


def ids(report):
    return {f.id: f.severity.value for f in report.findings()}


@pytest.mark.parametrize("builder,name,kind,subtype", [
    ("newsletter_html", "page.html", "html", "html"),
    ("smuggling_html", "page.htm", "html", "html"),
    ("svg_logo", "logo.svg", "svg", None),
    ("svg_redirect", "x.svg", "svg", None),
    ("hta_downloader", "x.hta", "html", "hta"),
    ("wsf_job", "x.wsf", "wsf", None),
])
def test_identified_from_content(web_fx, make_file, builder, name, kind, subtype):
    ft = identify(make_file(name, getattr(web_fx, builder)()))
    assert (ft.kind, ft.subtype or None) == (kind, subtype)
    assert not ft.mismatches


def test_html_named_hta_is_an_hta(web_fx, make_file):
    ft = identify(make_file("viewer.hta", web_fx.newsletter_html()))
    assert (ft.kind, ft.subtype) == ("html", "hta")


def test_hta_disguised_as_pdf(web_fx, make_file):
    ft = identify(make_file("invoice.pdf.hta", web_fx.hta_downloader()))
    assert "identify.double_extension" in {m.id for m in ft.mismatches}


def test_script_mentioning_html_stays_a_script(make_file):
    ft = identify(make_file("a.js", b'var t = "<html><body>";\nfunction f() { return t; }\n'))
    assert ft.kind == "script"


@pytest.mark.parametrize("builder,payload_name", [
    ("smuggling_html", "invoice.zip"),
    ("smuggling_split_html", "report.zip"),
    ("data_uri_download_html", "statement.zip"),
    ("svg_smuggling", "fax.zip"),
])
def test_smuggling_is_malicious_and_payload_triaged(web_fx, make_file, builder, payload_name):
    r = triage(make_file, "page.html", getattr(web_fx, builder)())
    assert r.verdict["value"] == "malicious"
    assert "V-MAL-11" in {x["rule"] for x in r.verdict["reasons"]}
    assert ids(r)["web.smuggling"] == "high"
    (child,) = r.children
    assert child["member"]["name"] == payload_name
    assert child["report"].file_type.kind == "zip"
    assert child["report"].children, "the smuggled archive's own members were triaged"


def test_smuggled_program(web_fx, make_file):
    r = triage(make_file, "page.html", web_fx.smuggling_html_exe())
    assert ids(r)["web.embedded_executable"] == "high"
    assert r.children[0]["report"].file_type.kind == "pe"
    assert r.verdict["value"] == "malicious"


@pytest.mark.parametrize("builder", ["newsletter_html", "csv_export_html", "svg_logo"])
def test_benign_pages_have_no_findings(web_fx, make_file, builder):
    r = triage(make_file, "page.html", getattr(web_fx, builder)())
    assert r.verdict["value"] == "no findings"
    assert not [f for f in r.findings() if f.id.startswith("web.")
                and f.severity.value in ("medium", "high")]
    assert r.children == []


def test_redirect_wrapper(web_fx, make_file):
    r = triage(make_file, "doc.html", web_fx.redirect_html())
    assert ids(r)["web.redirect_lure"] == "high"
    assert r.verdict["value"] == "suspicious"
    web = r.result("web").data
    assert web["navigations"][0]["target"].startswith("https://login.example.net/")


def test_svg_redirect_and_script(web_fx, make_file):
    r = triage(make_file, "fax.svg", web_fx.svg_redirect())
    assert ids(r)["web.svg_redirect"] == "high"
    assert ids(r)["web.svg_script"] == "high"
    assert r.verdict["value"] == "suspicious"


def test_credential_form(web_fx, make_file):
    r = triage(make_file, "login.html", web_fx.credential_form_html())
    f = next(x for x in r.findings() if x.id == "web.credential_form")
    assert f.severity.value == "high" and "microsoft" in f.detail
    assert r.verdict["value"] == "suspicious"


def test_credential_exfil_to_messaging_service(web_fx, make_file):
    r = triage(make_file, "login.html", web_fx.credential_exfil_html())
    assert ids(r)["web.credential_exfil"] == "high"
    assert r.verdict["value"] == "malicious" and r.verdict["rule"] == "V-MAL-13"


def test_hta_downloader(web_fx, make_file):
    r = triage(make_file, "viewer.hta", web_fx.hta_downloader())
    found = ids(r)
    assert found["web.hta"] == "medium"
    assert found["web.download_execute"] == "high"
    assert r.verdict["value"] == "malicious" and r.verdict["rule"] == "V-MAL-07"
    assert r.result("web").data["hta"]["windowstate"] == "minimize"


def test_plain_hta_is_flagged_but_not_suspicious(web_fx, make_file):
    r = triage(make_file, "tool.hta", web_fx.hta_plain())
    assert ids(r) == {"web.hta": "medium"}


def test_wsf_downloader(web_fx, make_file):
    r = triage(make_file, "job.wsf", web_fx.wsf_job())
    assert ids(r)["web.download_execute"] == "high"
    assert r.verdict["value"] == "malicious"


def test_html_attachment_in_email_is_triaged_as_a_page(web_fx, mail_fx, make_file):
    eml = mail_fx.build_eml(
        [("From", "billing@example.net"), ("To", "user@example.com"),
         ("Subject", "Invoice"), ("Date", "Mon, 19 Oct 2026 09:00:00 +0000")],
        text="See attached.", attachments=[("Invoice.html", "text/html",
                                            web_fx.smuggling_html())])
    r = triage(make_file, "invoice.eml", eml)
    (child,) = r.children
    assert child["report"].file_type.kind == "html"
    assert child["report"].verdict["value"] == "malicious"
    assert r.verdict["value"] == "malicious"


def test_payloads_respect_the_depth_limit(web_fx, make_file):
    from unopened.extraction import Limits

    path = make_file("page.html", web_fx.smuggling_html())
    r = pipeline.triage(path, Options(hunt=False, limits=Limits(max_depth=0)))
    assert r.children == []
    assert any("Embedded payload" in n.reason for n in r.not_checked)
    # The smuggling itself is still seen.
    assert "web.smuggling" in ids(r)


def test_reports_are_defanged_and_scriptless(web_fx, make_file):
    r = triage(make_file, "login.html", web_fx.credential_exfil_html())
    md = markdown.render(r)
    assert "api.telegram.org" not in md and "telegram[.]org" in md
    page = html_report.render(r)
    assert "<script" not in page
    assert "api.telegram.org" in json_report.render(r)  # raw values stay in JSON only
