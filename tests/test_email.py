"""Email analyzer (.eml and Outlook .msg): headers, sender authentication, look-alike
domains, links, forms and attachments, all from synthetic messages."""

from __future__ import annotations

import pytest

from unopened import pipeline
from unopened.analyzers import Options
from unopened.analyzers.mail import impersonated_brand, load_brands, org_domain
from unopened.extraction import Limits
from unopened.identify import identify, looks_like_email
from unopened.model import Severity
from unopened.report import markdown


def triage(path, **kw):
    return pipeline.triage(path, Options(**kw), isolate=False)


def email_ids(report):
    r = report.result("email")
    return {f.id: f.severity for f in r.findings}


# Identification -------------------------------------------------------------------------

def test_eml_is_identified_from_content(make_file, mail_fx):
    ft = identify(make_file("message.eml", mail_fx.phish_eml()))
    assert (ft.kind, ft.subtype) == ("email", "eml")
    assert not ft.mismatches


def test_eml_saved_as_txt_is_not_a_mismatch(make_file, mail_fx):
    assert not identify(make_file("message.txt", mail_fx.newsletter_eml())).mismatches


def test_msg_is_outlook(make_file, mail_fx):
    ft = identify(make_file("message.msg", mail_fx.phish_msg()))
    assert (ft.kind, ft.subtype) == ("ole", "outlook")


@pytest.mark.parametrize("text", [
    b"$a = 1\nWrite-Host 'From: x'\n",
    b"Name: build\nVersion: 2\nAuthor: me\n\nnotes",
    b"From: a\n",
])
def test_other_text_is_not_email(text):
    assert not looks_like_email(text)


def test_mbox_separator_line_is_accepted(mail_fx):
    assert looks_like_email(b"From someone@example.com Mon Oct 19 09:00:00 2026\n"
                            + mail_fx.newsletter_eml())


# Helpers --------------------------------------------------------------------------------

@pytest.mark.parametrize("host,expected", [
    ("login.micros0ft-support.example.com", "microsoft"),
    ("secure-paypa1.example.net", "paypal"),
    ("rnicrosoft.example.com", "microsoft"),
    ("login.microsoftonline.com", None),
    ("tenant.sharepoint.com", None),
    ("pineapple.example.com", None),
    ("www.example.com", None),
])
def test_impersonated_brand(host, expected):
    assert impersonated_brand(host, load_brands()) == expected


@pytest.mark.parametrize("host,expected", [
    ("mail.example.com", "example.com"),
    ("a.b.example.co.uk", "example.co.uk"),
    ("example.com", "example.com"),
])
def test_org_domain(host, expected):
    assert org_domain(host) == expected


# Full triage ----------------------------------------------------------------------------

def test_phishing_email(make_file, mail_fx):
    report = triage(make_file("report.eml", mail_fx.phish_eml()))
    ids = email_ids(report)
    for fid in ("email.dmarc_fail", "email.lookalike_sender", "email.html_form",
                "email.lookalike_link", "email.attachment_executable"):
        assert ids[fid] == Severity.HIGH, fid
    for fid in ("email.auth_fail", "email.reply_to_mismatch", "email.link_text_mismatch",
                "email.ip_link", "email.attachment_html", "email.display_name_brand"):
        assert ids[fid] == Severity.MEDIUM, fid
    assert report.verdict["value"] == "malicious"
    assert report.verdict["rule"] == "V-MAL-06"
    members = {c["member"]["name"]: c["report"] for c in report.children}
    assert members["Invoice.pdf.lnk"].file_type.kind == "lnk"
    assert members["Invoice.pdf.lnk"].verdict["value"] == "malicious"
    assert members["Statement.html"].verdict["value"] == "no findings"


def test_only_the_topmost_authentication_results_count(make_file, mail_fx):
    """The lower header claims dmarc=pass; only the receiving server's (topmost) counts."""
    report = triage(make_file("report.eml", mail_fx.phish_eml()))
    auth = report.result("email").data["auth"]
    assert auth["dmarc"] == "fail"
    assert "forged" not in auth["raw"]


def test_newsletter_is_quiet(make_file, mail_fx):
    report = triage(make_file("news.eml", mail_fx.newsletter_eml()))
    assert {s for s in email_ids(report).values()} <= {Severity.INFO}
    assert report.verdict["value"] == "no findings"


def test_display_name_with_another_address(make_file, mail_fx):
    report = triage(make_file("bec.eml", mail_fx.display_name_spoof_eml()))
    assert email_ids(report)["email.display_name_address"] == Severity.HIGH
    assert report.verdict["value"] == "suspicious"


def test_missing_authentication_is_listed_not_checked(make_file, mail_fx):
    report = triage(make_file("draft.eml", mail_fx.headers_only_eml()))
    assert any("Sender authentication" in n.check or "Sender authentication" in n.reason
               for n in report.not_checked)
    assert report.verdict["confidence"] == "low"


def test_attached_message_is_triaged_as_email(make_file, mail_fx):
    report = triage(make_file("fw.eml", mail_fx.nested_eml()))
    child = report.children[0]["report"]
    assert child.file_type.kind == "email"
    assert "email.lookalike_sender" in email_ids(child)
    assert report.verdict["rule"] == "V-SUS-02"


def test_outlook_msg(make_file, mail_fx):
    report = triage(make_file("report.msg", mail_fx.phish_msg()))
    data = report.result("email").data
    assert data["format"] == "msg"
    assert data["auth"]["dmarc"] == "fail"
    assert [a["name"] for a in data["attachments"]] == ["Invoice.pdf.lnk"]
    assert report.children[0]["report"].file_type.kind == "lnk"
    assert report.verdict["value"] == "malicious"


def test_attachment_over_the_member_limit_is_reported(make_file, mail_fx):
    report = triage(make_file("report.eml", mail_fx.phish_eml()),
                    limits=Limits(max_member_size=100))
    data = report.result("email").data
    skipped = [m for m in data["members"] if m.get("skipped")]
    assert {m["name"] for m in skipped} == {"Invoice.pdf.lnk"}
    assert any("Invoice.pdf.lnk" in n.reason or "Invoice.pdf.lnk" in n.check
               for n in report.not_checked)


def test_damaged_message_does_not_crash(make_file, mail_fx):
    data = mail_fx.phish_eml()
    report = triage(make_file("broken.eml", data[: len(data) // 2] + b"\x00\xff" * 50))
    assert report.result("email").status in ("ok", "partial")


def test_report_has_email_section_and_no_live_links(make_file, mail_fx):
    report = triage(make_file("report.eml", mail_fx.phish_eml()))
    md = markdown.render(report)
    assert "## Email" in md
    assert "https://" not in md and "http://" not in md
    assert "hxxps://login.micros0ft-support.example[.]com" in md


def test_hunt_queries_find_other_deliveries(make_file, mail_fx):
    report = triage(make_file("report.eml", mail_fx.phish_eml()))
    values = report.hunt["values"]
    assert values["senders"] == ["no-reply@micros0ft-support.example.com"]
    assert values["subjects"] == ["Action required: mailbox quota"]
    kql = "\n".join(q["query"] for q in report.hunt["platforms"]["sentinel"]["queries"])
    assert "EmailEvents" in kql and "EmailUrlInfo" in kql
