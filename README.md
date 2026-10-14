# unopened

Static triage of a suspicious file for SOC analysts who are not reverse engineers.
Give it one file; it writes one plain-language report answering: what is this file, what
can it do, which indicators can I pivot on, and what was *not* checked.

The file is never executed, opened in its native application, or rendered. Every check
reads its bytes and nothing more.

## Safety guarantees

- **Static only.** No analyzer runs the sample or loads it as code, macros or scripts.
  A test walks the source tree and fails if it finds process-spawning, network or
  dynamic-code primitives. Another test blocks sockets and process creation for the
  whole test run.
- **Defanged output.** Every URL, domain, IP address and email in the Markdown report
  is defanged (`hxxp://example[.]com`, `10.0.0[.]1`, `user[@]example[.]com`). As a final
  pass, the whole document is scanned and anything still link-like is defanged too.
  JSON keeps original values only in fields named `raw`.
- **No network by default.** The only network code is the opt-in reputation lookup
  (`--reputation`), in a single module that is not even imported otherwise. It sends
  SHA256 hashes only; the file and its name never leave the machine. A test scans the
  source tree and allows network imports in that one module only.
- **Bounded extraction.** Archives, disk images, PDF attachments and Office parts are
  extracted within limits on nesting depth, member count, total size, per-member size
  and compression ratio. Limits are checked against the headers and again while bytes
  are written, because headers can lie. A zip bomb stops with a clear message.
- **Members never choose their own path.** Extracted files go to a private temporary
  directory (0700) under index names (`0001.bin`), are created 0600 and never made
  executable, and the directory is deleted when triage ends, even after an error.
- **Fail loudly.** If a check crashes, times out, cannot parse the file, or needs a
  library that is missing, the report says so near the top. Planned checks that this
  version does not do yet are listed under **Not checked**. A missing check never
  looks like a clean result, and lowers the verdict's confidence.
- **Transparent verdicts.** The verdict comes from fixed rules listed in
  [docs/verdict-rules.md](docs/verdict-rules.md), never from a model. Every report shows
  which rules matched and the findings that triggered them.

## Install

Python 3.11 or newer.

```sh
python -m venv .venv && . .venv/bin/activate
pip install -e ".[all,dev]"
```

Every analyzer beyond the PE basics is optional. If a library is missing, the report
marks that check **UNAVAILABLE** and says how to install it.

| Extra | Installs | Enables |
|---|---|---|
| `fuzzy` | py-tlsh | TLSH fuzzy hash (needs a C++ compiler) |
| `office` | oletools, defusedxml | Office macro, embedded object and external reference analysis |
| `lnk` | LnkParse3 | Shortcut analysis |
| `yara` | yara-python | YARA scanning |
| `capa` | flare-capa | Capabilities and ATT&CK mapping (heavy: brings vivisect) |
| `archive` | py7zr, pyzipper, pycdlib | 7z, AES-encrypted ZIP and ISO extraction (plain and ZipCrypto ZIP work without it) |
| `pdf` | pypdf | PDF JavaScript, actions and attachments |
| `all` | all of the above | |

**Authenticode on OpenSSL 3.0.10 or newer.** signify depends on oscrypto. The oscrypto
1.3.0 release on PyPI cannot parse OpenSSL version strings like `3.0.13`, so signify
fails to load. Install the fixed upstream revision:

```sh
pip install "oscrypto @ git+https://github.com/wbond/oscrypto.git@1547f535001ba568b239b8797465536759c742a3"
```

Without that fix the tool still runs, but the report marks the signature check
**UNAVAILABLE** and explains why.

## Usage

```sh
unopened triage suspicious.bin                       # Markdown to stdout
unopened triage suspicious.bin --format json         # JSON to stdout
unopened triage suspicious.bin --format both --out reports/   # reports/<sha256>.md and .json
unopened triage suspicious.bin --yara-rules ~/rules/yara --capa-rules ~/rules/capa
```

### Rules

No YARA or capa rules ship with this tool; point it at your own. The capa pip package
does not include rules, so download a capa-rules release matching your capa version
(REMnux ships both). Set them once in your shell instead of on every run:

```sh
export UNOPENED_YARA_RULES=~/rules/yara        # directory (searched recursively) or one file
export UNOPENED_CAPA_RULES=~/rules/capa-rules
export UNOPENED_CAPA_SIGNATURES=~/rules/capa-sigs   # optional FLIRT signatures
```

If no rules are configured, the report says so prominently: an unconfigured YARA scan is
reported as not run, never as "no matches".

| Option | Default | Meaning |
|---|---|---|
| `--format md\|json\|both` | `md` | Report format; `both` requires `--out` |
| `--out DIR` | stdout | Write `<sha256>.md` / `<sha256>.json` into DIR |
| `--allowlist PATH` | built-in | TOML allowlist of known-benign indicators |
| `--yara-rules PATH` | `$UNOPENED_YARA_RULES` | YARA rules directory or file |
| `--capa-rules DIR` | `$UNOPENED_CAPA_RULES` | capa rules directory |
| `--capa-signatures DIR` | `$UNOPENED_CAPA_SIGNATURES` | capa FLIRT signatures (library-function recognition) |
| `--capa-timeout SECONDS` | `300` | Time limit for capa, which is slow on large binaries |
| `--max-size SIZE` | `200MB` | Refuse larger files (`5000000`, `50MB`, `1G`); also the per-member extraction limit |
| `--timeout SECONDS` | `60` | Per-analyzer time limit; a stopped analyzer is reported as TIMED OUT |
| `--file-timeout SECONDS` | `900` | Time budget for the whole file, archive members included; checks and members still pending when it runs out are listed under Not checked and the verdict's confidence drops to low |
| `--reputation` | off | Look up SHA256 hashes at MalwareBazaar, then VirusTotal (see below) |
| `--max-lookups N` | `20` | Hashes looked up per run (file plus extracted members) |
| `--hunt-days N` | `30` | Time window for the SIEM hunt queries |
| `--no-hunt` | | Do not generate hunt queries |
| `--archive-password PASSWORD` | `infected` | Password to try on encrypted archives; repeat for more |
| `--max-depth N` | `3` | How deep nested archives are extracted; deeper ones are listed, not analyzed |
| `--max-files N` | `1000` | Members extracted in total, across all nesting levels |
| `--max-total-size SIZE` | `500MB` | Bytes extracted in total |
| `--max-ratio N` | `100` | Highest compression ratio accepted for a member over 1 MB |
| `--min-string-length N` | `5` | Shortest printable run treated as a string |
| `--max-strings N` | `200000` | Stop examining strings after N (reported under Not checked) |

Exit codes: `0` report written (whatever it found), `2` usage, configuration or
output-write error, `3` the input could not be read or was too large.

## Behavior patterns

Most single signals (an embedded program, a download, a resolved API) are common in
legitimate software, so they are reported at LOW. `src/unopened/data/behaviors.toml`
names combinations that, together, describe what malware does, and adds one finding
when all parts are present, citing the exact evidence.

| Pattern | Fires when | Severity |
|---|---|---|
| Reverse shell | unsigned + capa: create reverse shell | HIGH |
| Keystroke logging | unsigned + capa: log keystrokes | HIGH |
| Collects files and uploads them | unsigned + enumerates files + sends files over HTTP | HIGH |
| Shellcode-style API loading | no or almost no imports + walks loader structures or parses exports | HIGH |
| Hidden strings and runtime-resolved APIs | unsigned + stack strings + many runtime-linked functions or parses exports | HIGH |
| Drops an embedded program | unsigned + embedded PE + extracts a resource + writes a file | MEDIUM |
| Downloads and runs a file | unsigned + downloads + writes and runs or starts a process | MEDIUM |
| Starts itself through a Run key | capa: persist via Run registry key | MEDIUM |
| Deletes itself | capa: self delete | MEDIUM |
| Obfuscated script that sets up persistence | script is obfuscated + scheduled task or Run key | HIGH |
| Process-injection imports under an untrusted signature | signature fails verification + process-injection imports | HIGH |
| Embedded program, with a YARA match | unsigned + embedded PE + any YARA match | HIGH |
| Disk image hiding files next to programs | hidden files + programs, shortcuts or scripts in the image | HIGH |
| Bypasses User Account Control | unsigned + capa: bypass UAC | HIGH |
| .NET program that loads hidden code from itself | unsigned .NET + high-entropy code section (MEDIUM) + loads or invokes a .NET assembly | HIGH |
| Finds Windows functions by hash | unsigned + capa: resolve function by ... hash | HIGH |
| Script with a huge encoded line that reaches Windows | COM objects, commands or Execute/Eval + a line over 500,000 characters | HIGH |
| Runs code it assembles at run time | VBScript Execute/Eval + builds strings with Mid, StrReverse or Chr (or is obfuscated) | HIGH |
| Obfuscated batch file that reads itself | batch obfuscated (encodings or 50+ `%var:~n,m%` substrings) + refers to its own file (`%~f0`) | HIGH |

The five from "Process-injection imports" to "Bypasses User Account Control" were added
after holdout set 1, and the last five after holdout set 2 (see
[docs/validation.md](docs/validation.md)), from combinations seen on real samples the
earlier rules had not been written against.

Archives and disk images also get a cross-member check: a validly signed program shipped
next to a DLL that calls shellcode (capa: execute shellcode via indirect call, plus RWX
memory or an embedded PE) and is unsigned, fails verification or is signed by a different
organization is reported as DLL side-loading (HIGH).

"Unsigned" means a positive not-signed result, or a signature that fails verification
(untrusted certificate, altered file), since that lends no trust. On a file with a valid
signature these patterns are kept at LOW. If the signature could not be checked at all,
they do not fire and the report says so. Patterns likely to match legitimate
unsigned installers start at MEDIUM and are promoted only after the benign-corpus run.

## Hash reputation (opt-in)

```sh
export ABUSECH_API_KEY=...   # free key from https://auth.abuse.ch/ (MalwareBazaar)
export VT_API_KEY=...        # optional, VirusTotal
unopened triage suspicious.bin --reputation
```

- Only the SHA256 of the file (and of extracted members, up to `--max-lookups`) is
  sent, over HTTPS with certificate checks and a 10-second timeout. Nothing is uploaded.
- Keys are read from the environment only, so they never appear in shell history,
  process listings or reports.
- Every source's outcome is reported: found, not found, skipped (no key), rate limited
  (VirusTotal's free tier allows 4 lookups a minute; later lookups are skipped, not
  retried) or error. A hash that no source knows is **unknown, not clean**.
- Verdict rules V-REP-01 to V-REP-03 use the answers: known to MalwareBazaar or 5 or
  more VirusTotal engines means malicious; 1 to 4 engines means suspicious (low).

## Validation (for maintainers)

`scripts/validate.py` runs triage over a folder of samples and compares the results with
an expectations CSV, writing `validation-results/results.csv` and
`validation-results/summary.md` (verdicts by label, behavior coverage, misses, false
positives, incomplete checks, runtime). Run it **only inside an isolated analysis VM**
when the folder holds real malware.

```sh
python scripts/validate.py ~/samples/pma --expectations validation/pma-labs.csv \
    -- --capa-rules ~/rules/capa --yara-rules ~/rules/yara
python scripts/validate.py ~/corpus --label benign      # false-positive run
python scripts/validate.py --list-behaviors             # labels for the CSV
```

capa is slow on large programs (minutes each in a VM) and single-threaded, so set
`--jobs` to the VM's CPU count (`nproc`). Results are written to `results.csv` as each
file finishes; after an interruption, rerun with `--resume` to skip the files already
done.

The outputs hold labels and rule IDs, never raw indicators; `--keep-reports` also keeps
the full JSON reports, which do contain raw values under `raw` keys.

## Hunt queries

Every report ends with ready-made searches for the file's hashes and names (including
extracted members) and its network indicators, for **Splunk** (SPL, raw terms and CIM
data models), **Microsoft Sentinel / Defender** (KQL over `DeviceFileEvents`,
`DeviceProcessEvents`, `EmailAttachmentInfo`, `DeviceNetworkEvents`, `DnsEvents`) and
**Elastic** (Kibana KQL over ECS fields). Private and reserved IP addresses are left
out, and each list holds at most 50 values.

Hash and file-name queries in the Markdown report can be pasted as they are. Network
values there are defanged, like everywhere else in the report. The paste-ready raw
queries are written to `<sha256>.hunt.txt` when you use `--out`, and are in the JSON
report under `hunt.raw`.

## Verdicts

Every report starts with one of **malicious**, **suspicious**, **could not analyze** or
**no findings**, plus a confidence (high, medium, low) and the rule that decided it. The
rules, in order, are in [docs/verdict-rules.md](docs/verdict-rules.md), generated from
`src/unopened/verdict.py`. Briefly:

- **Malicious** needs specific evidence: a high-severity YARA match, auto-run macros that
  run or download things, a shortcut launching PowerShell or similar with an encoded or
  hidden command, DDE, remote template injection, an embedded executable, a script that
  downloads and runs code, a PDF Launch action, a malicious archive member, or HIGH
  findings from two different analyzers.
- **Suspicious**: any single HIGH finding, an obfuscated script that runs code, a
  suspicious member, or three or more MEDIUM findings.
- **Could not analyze**: the analyzer for the file's type failed, encrypted content could
  not be opened, or no archive member could be extracted.
- **No findings** only means the checks that ran found nothing decisive. It is never a
  statement that the file is safe, and drops to low confidence when any check did not
  complete (including YARA or, for PE files, capa not being configured).

Archives, disk images and PDFs take the most severe verdict among their own findings and
their members.

## What this version checks (milestones 1 to 4)

| Step | What it does |
|---|---|
| Type identification | Uses magic bytes and structure, never the extension. Recognizes PE (EXE/DLL/driver, PE32/PE32+), MZ without a PE header, OLE, OOXML (Word/Excel/PowerPoint, VBA project present), ZIP, LNK, PDF, 7z, ISO, PowerShell/JavaScript/VBScript/batch (heuristic), text. Flags extension mismatches (HIGH when a program wears a document, image or archive extension; LOW for storage names like `.bin` or `.malware`), double extensions (`invoice.pdf.exe`), padding spaces and Unicode direction-override tricks. |
| Hashes | MD5, SHA1, SHA256; imphash for PE; TLSH when `py-tlsh` is installed. |
| PE | Headers, compile timestamp (zeroed, future, implausible, Delphi default), sections with entropy and permissions, packer section names, W+X sections, entry point placement, imports grouped by behavior (`data/pe_imports.toml`), exports, PDB path, overlay, truncation, .NET detection, parser anomalies. |
| Authenticode | Signature presence and validity (offline, against the Microsoft root list bundled with signify), signer, issuer and timestamp. Revocation is not checked. |
| Strings and indicators | ASCII and UTF-16LE strings, then URLs, domains (validated against a TLD list), IPv4/IPv6 (with private/public tags), emails, file paths, UNC paths, and registry keys (persistence locations tagged). Indicators that analyzers decode (macro source, shortcut arguments, decoded PowerShell, the LNK creator's host name and MAC address) join the same list, tagged with their source. |
| capa (PE) | Capabilities from your capa rules, with namespace, ATT&CK technique IDs and MBC behaviors, grouped by tactic. Reports when capa's limitation rules say a file is packed or wrapped. |
| YARA | Every `.yar`/`.yara` file under the rules path. The namespace is the file's relative path. Reports rule, tags, meta and matched strings (capped, shown as text or hex). A file that fails to compile is reported and the others still run. Severity comes from a rule's `severity` or `score` meta. |
| Office (OLE and OOXML) | VBA macros (module source), auto-run triggers, suspicious keywords, VBA stomping, Excel 4.0 (XLM) macro sheets, embedded OLE packages (with file names), ActiveX parts, DDE fields, and external relationships such as remote template injection. Legacy files get a subtype (Word/Excel/PowerPoint/MSI/MSG) for extension checks. |
| LNK | Target, arguments, working directory, icon, comment and window style. Flags LOLBin targets and arguments (`data/lolbins.toml`, editable), encoded PowerShell (decoded as text for display only), hidden windows, whitespace padding, borrowed icons, network targets, and data appended after the shortcut. |
| Archives and disk images | ZIP (plain, ZipCrypto, AES), 7z (including encrypted headers) and ISO (Joliet, Rock Ridge, UDF, ISO 9660). Tries no password, then `infected`, then any `--archive-password`. Each member is triaged recursively with the full pipeline. Flags path-traversal and deceptive names, hidden files in images, shortcuts next to hidden files, programs inside archives, unknown passwords, decompression bombs and limits reached. |
| Scripts | PowerShell, JavaScript/JScript, VBScript and batch. Deobfuscation by text transformation only (base64 including `-EncodedCommand`, character codes, string concatenation), repeated up to five rounds. Keywords per language from `data/script_keywords.toml` (editable), plus a combined "downloads and runs code" finding. Decoded text feeds the indicator list. |
| PDF | Raw keyword counts with `#xx`-escaped names decoded (and flagged), then JavaScript source with its trigger (OpenAction, /AA), Launch actions, URIs, XFA and rich media. Attachments are extracted within the limits and triaged recursively. |

Not in this version (always listed under **Not checked** in the report): FLOSS-decoded
strings;
extraction of files embedded in Office documents; DDE in legacy binary Word files; VHD
and other disk-image formats.

### How the heavier libraries stay static

- **capa** disassembles with vivisect (or reads .NET metadata). Some vivisect passes
  *emulate* instructions inside a pure-Python emulator to recover values such as call
  arguments. Nothing runs natively, the operating system never loads the sample, and no
  analysis workspace is saved next to it.
- **olevba** extracts macro source as text. Its VBA expression deobfuscation stays off,
  and XLMMacroDeobfuscator (which emulates Excel 4.0 formulas) is disabled even if it is
  installed. XLM detection in legacy `.xls` files parses BIFF records only.
- OOXML parts are read by this tool within the size and ratio limits and handed to
  oletools as bytes. XML is parsed with defusedxml.
- **pypdf** parses and decompresses PDF objects with lowered decompression limits. Its
  optional external `jbig2dec` decoder is disabled, so no program ever runs on sample
  data. JavaScript is only read.
- **Scripts** are never evaluated: deobfuscation rewrites recognizable encodings into
  string literals and stops after a fixed number of rounds and output size.
- Every analyzer runs in its own worker process with a time limit.

Defanging is applied to the whole Markdown report, macro source excerpts included. Code
like `WScript.Shell` can therefore show as `WScript[.]Shell`, because `.shell` is a
real top-level domain and chat clients would turn it into a link.

## Allowlist

`src/unopened/data/allowlist.toml` lists known-benign noise such as XML namespaces and
certificate-authority CRL/OCSP hosts. Matches are removed from the indicator tables, but
the report still shows how many were hidden. Copy the file, edit it, and pass it with
`--allowlist`. Keep it conservative: anything on it can hide abuse of that domain, so
never add file-sharing, paste, code-hosting or cloud-storage services.

Sections: `[domains] exact/suffix`, `[urls] prefix`, `[ips] cidr`, `[emails] exact`,
`[paths] prefix`, `[registry] prefix`. Unknown sections or malformed entries are errors.

`src/unopened/data/tlds.txt` is a snapshot of top-level domains taken from the ICANN
section of the Public Suffix List. It is used so that strings like `kernel32.dll` are
not mistaken for domains.

## Development

```sh
pytest                 # full suite; fixtures are generated synthetically at test time
ruff check src tests
```

Fixtures are built byte by byte by `tests/fixtures/`:
- `build.py`: minimal PE images whose only code is `ret`.
- `office.py`: an OLE writer plus a VBA project whose only macro shows a message box,
  with keyword bait inside strings that never run.
- `lnk.py`: shortcuts whose commands are inert text.
- `archives.py`: ZIP (including a small ZipCrypto writer, since no library writes it),
  AES ZIP, 7z, ISO, hand-assembled PDFs and scripts whose "payloads" are inert text, plus
  bombs, deep nesting and traversal names for the limit tests.

They all use documentation-only domains, IP ranges and MAC addresses. Test-only YARA
and capa rules live in `tests/rules/`. No sample, real customer document or real
indicator is ever committed (see `.gitignore` and `tests/fixtures/README.md`).

After changing a verdict rule, regenerate the documentation (a test checks it):

```sh
python -m unopened.verdict > docs/verdict-rules.md
```

**False-positive measurement.** Point the corpus test at a directory of ordinary,
benign installers and documents kept outside the repository:

```sh
UNOPENED_CORPUS=~/benign-corpus pytest -m corpus -s
UNOPENED_CORPUS=~/benign-corpus UNOPENED_CORPUS_MAX_FLAGGED=0.05 pytest -m corpus
```

It prints the share of benign files judged malicious or suspicious, the verdict and
deciding-rule distribution, and which findings fire most. It fails on any analyzer
crash, or when the share exceeds the optional limit.

Test with real malware only inside an isolated analysis VM (for example REMnux) with no
shared folders or clipboard. Keep samples zipped with the password `infected`.
