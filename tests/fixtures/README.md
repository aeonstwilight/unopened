# Test fixtures

Every fixture is synthetic and benign. `build.py` generates them byte by byte at test
time, so no binaries are committed:

- PE files: minimal, well-formed PE32/PE32+ images whose only code is a `ret`
  instruction. Suspicious-looking traits (injection-related import *names*, a `UPX0`
  section, high-entropy data, a future timestamp) are just table entries and random bytes.
- Network values use documentation-only names and ranges: `example.com/.org/.net`
  (RFC 2606) and `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` (RFC 5737).
- `web.py` (HTML, SVG, HTA, WSF, RTF, VHD): smuggled "payloads" are the `ret`-only PE
  above or small archives of text; the Equation Editor "exploit" is a font name of
  repeated `A`s with no code. The credential-exfiltration page names a Telegram bot API
  host because that is what the detection looks for; nothing contacts it.
- The EICAR test string is the only "detected" content allowed, for later YARA and
  reputation tests.

Never add real malware, real customer documents, or indicators from a real investigation.
Write fixtures to disk for manual runs with `python tests/fixtures/build.py OUTPUT_DIR`.
