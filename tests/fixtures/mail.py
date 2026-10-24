"""Synthetic email fixtures: .eml messages built with the standard library and an Outlook
.msg built with the OLE writer from fixtures.office.

Every address and link uses reserved names (example.com, example.net, .example, RFC 2606)
or the documentation IP range (192.0.2.0/24, RFC 5737). The "phishing" message only looks
like one: its attachments are the harmless synthetic shortcut and an inert HTML page.
"""

from __future__ import annotations

from email.message import EmailMessage

from . import lnk
from .office import build_ole

PHISH_HTML = """<html><body>
<p>Your mailbox is almost full. Sign in to keep receiving mail.</p>
<p><a href="https://login.micros0ft-support.example.com/owa/?u=1">https://login.microsoftonline.com</a></p>
<p><a href="http://192.0.2.10/verify">Verify now</a></p>
<form action="https://collect.example.net/post" method="post">
  <input type="text" name="user"><input type="password" name="pass">
</form>
</body></html>"""

NEWSLETTER_HTML = """<html><body>
<p>This month's notes are on <a href="https://www.example.com/news/october">www.example.com</a>.</p>
</body></html>"""


def build_eml(headers: list[tuple[str, str]], text: str = "", html: str = "",
              attachments: list[tuple[str, str, bytes]] = ()) -> bytes:
    msg = EmailMessage()
    for name, value in headers:
        msg[name] = value
    if text:
        msg.set_content(text)
    if html:
        if text:
            msg.add_alternative(html, subtype="html")
        else:
            msg.set_content(html, subtype="html")
    for name, ctype, data in attachments:
        maintype, subtype = ctype.split("/", 1)
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
    return msg.as_bytes()


def phish_eml() -> bytes:
    return build_eml(
        [
            ("Received", "from mail.example.net (mail.example.net [192.0.2.25]) by "
                         "mx.example.com; Mon, 19 Oct 2026 09:00:00 +0000"),
            ("Authentication-Results",
             "mx.example.com; spf=fail smtp.mailfrom=example.net; dkim=none; "
             "dmarc=fail header.from=micros0ft-support.example.com"),
            ("Authentication-Results", "forged.example.net; spf=pass; dkim=pass; dmarc=pass"),
            ("From", "Microsoft 365 <no-reply@micros0ft-support.example.com>"),
            ("Reply-To", "helpdesk@example.org"),
            ("Return-Path", "<bounce@example.net>"),
            ("To", "user@example.com"),
            ("Subject", "Action required: mailbox quota"),
            ("Date", "Mon, 19 Oct 2026 09:00:00 +0000"),
            ("Message-ID", "<phish-1@example.net>"),
        ],
        text="Your mailbox is almost full. Sign in: https://login.micros0ft-support.example.com/owa",
        html=PHISH_HTML,
        attachments=[
            ("Invoice.pdf.lnk", "application/octet-stream", lnk.encoded_powershell()),
            ("Statement.html", "text/html", b"<html><body>Inert test page</body></html>"),
        ],
    )


def newsletter_eml() -> bytes:
    return build_eml(
        [
            ("Received", "from out.example.com by mx.example.com; Mon, 19 Oct 2026 08:00:00 +0000"),
            ("Authentication-Results", "mx.example.com; spf=pass smtp.mailfrom=example.com; "
                                       "dkim=pass header.d=example.com; dmarc=pass"),
            ("From", "Example News <news@example.com>"),
            ("To", "user@example.com"),
            ("Subject", "October notes"),
            ("Date", "Mon, 19 Oct 2026 08:00:00 +0000"),
            ("Message-ID", "<news-10@example.com>"),
        ],
        text="This month's notes: https://www.example.com/news/october",
        html=NEWSLETTER_HTML,
    )


def display_name_spoof_eml() -> bytes:
    return build_eml(
        [
            ("Received",
             "from mail.example.net by mx.example.com; Mon, 19 Oct 2026 10:00:00 +0000"),
            ("Authentication-Results", "mx.example.com; spf=pass; dkim=pass; dmarc=pass"),
            ("From", '"ceo@example.com" <someone@example.net>'),
            ("To", "finance@example.com"),
            ("Subject", "Quick favor"),
            ("Message-ID", "<bec-1@example.net>"),
        ],
        text="Are you at your desk? I need a wire sent today.",
    )


def headers_only_eml() -> bytes:
    """A message saved before delivery: no Received or Authentication-Results headers."""
    return build_eml(
        [("From", "Alex <alex@example.com>"), ("To", "sam@example.com"),
         ("Subject", "Draft"), ("Date", "Mon, 19 Oct 2026 11:00:00 +0000"),
         ("Message-ID", "<draft-1@example.com>")],
        text="See you at three.",
    )


def nested_eml() -> bytes:
    """A message carrying another message as an attachment (message/rfc822)."""
    inner = EmailMessage()
    inner["From"] = "Microsoft 365 <no-reply@micros0ft-support.example.com>"
    inner["To"] = "user@example.com"
    inner["Subject"] = "Original"
    inner["Message-ID"] = "<inner-1@example.net>"
    inner.set_content("Sign in: https://login.micros0ft-support.example.com/owa")
    outer = EmailMessage()
    outer["From"] = "User <user@example.com>"
    outer["To"] = "soc@example.com"
    outer["Subject"] = "FW: suspicious email"
    outer["Message-ID"] = "<report-1@example.com>"
    outer.set_content("Reporting the attached message.")
    outer.add_attachment(inner)
    return outer.as_bytes()


def _utf16(text: str) -> bytes:
    return text.encode("utf-16-le")


def phish_msg() -> bytes:
    """An Outlook .msg with saved transport headers, a body and one attachment."""
    transport = (
        "Received: from mail.example.net by mx.example.com; Mon, 19 Oct 2026 09:00:00 +0000\r\n"
        "Authentication-Results: mx.example.com; spf=fail; dkim=none; dmarc=fail\r\n"
        "From: Microsoft 365 <no-reply@micros0ft-support.example.com>\r\n"
        "Reply-To: helpdesk@example.org\r\n"
        "To: user@example.com\r\n"
        "Subject: Action required: mailbox quota\r\n"
        "Message-ID: <phish-msg-1@example.net>\r\n"
    )
    att = "__attach_version1.0_#00000000"
    streams = {
        "__substg1.0_007D001F": _utf16(transport),
        "__substg1.0_0037001F": _utf16("Action required: mailbox quota"),
        "__substg1.0_1000001F": _utf16("Sign in: https://login.micros0ft-support.example.com/owa"),
        f"{att}/__substg1.0_3707001F": _utf16("Invoice.pdf.lnk"),
        f"{att}/__substg1.0_37010102": lnk.encoded_powershell(),
        "__properties_version1.0": bytes(32),
    }
    return build_ole(streams)
