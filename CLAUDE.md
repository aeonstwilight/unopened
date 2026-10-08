# unopened: static malware triage for SOC analysts

## What this is

A command-line tool that takes a suspicious file and produces one plain-language triage report for a SOC analyst who is not a reverse engineer. It answers: what is this file, what can it do, what indicators can I pivot on, and how confident is the verdict.

It is a new, standalone project. Do not reference, copy from, or model it on any other repository.

## Hard rules (never break these)

1. **Never execute, open, or render a sample.** Static analysis only. No subprocess call may run a sample, and no library call may load it as executable code, macros, or scripts.
2. **Defang every indicator in human-readable output** (`hxxp://`, `example[.]com`, `10.0.0[.]1`). JSON output may carry raw values in a field explicitly named `raw`.
3. **No network access by default.** Reputation lookups are opt-in with a flag, send **hashes only**, and never upload a file.
4. **Bound all extraction.** Recursive archive extraction must enforce limits on depth, file count, total uncompressed size, and compression ratio, so zip bombs fail safely with a clear message.
5. **Never commit real malware.** Real samples live outside the repo. Tests use benign, synthetic fixtures only (see Testing).
6. **Fail loudly, never silently.** If an analyzer crashes, times out, or cannot parse a file, the report says so. A skipped check must never look like a clean result.

## Scope for version 1

### Supported inputs
- PE files (EXE, DLL)
- Office documents: legacy OLE (doc/xls) and OOXML (docx/xlsm and similar)
- Windows shortcuts (LNK)
- Scripts: PowerShell, JavaScript, VBScript, batch
- PDF
- Archives and disk images: ZIP (including password `infected`), 7z, ISO

### Pipeline
1. **Identify** the type from content (magic bytes), not the extension. Flag mismatches such as `invoice.pdf.exe` or a PE inside a `.docx` name.
2. **Hash**: MD5, SHA1, SHA256; imphash for PE; a fuzzy hash (TLSH or ssdeep) when available.
3. **Type-specific analysis**
   - PE: headers, compile timestamp, sections and entropy (packing indicators), imports of interest, signature presence and validity, then capa capabilities mapped to MITRE ATT&CK.
   - Office: macros present, auto-execution triggers, suspicious keywords, embedded objects, external template references (via oletools).
   - LNK: target path, arguments, working directory, icon location; flag LOLBins and encoded command lines.
   - Scripts: basic deobfuscation only (base64, char-code arrays, string concatenation) applied as text transformations, never by running the script.
   - PDF: JavaScript, OpenAction/Launch actions, embedded files.
   - Archives and images: extract within limits, then triage each member recursively.
4. **Strings and indicators**: extract strings (FLOSS where available, plain strings otherwise), then URLs, domains, IPs, email addresses, file paths and registry keys. Filter known-benign noise using an editable allowlist file.
5. **YARA**: scan with a configurable rules directory. Report rule name, namespace, and matched strings.
6. **Optional reputation lookup** (flag-gated, hash only): MalwareBazaar first, VirusTotal second if an API key is set. Record which sources answered and which did not.
7. **Verdict**: one of `malicious`, `suspicious`, `no findings`, `could not analyze`, plus a confidence level. The verdict is produced by transparent, documented rules, not a model. Every verdict lists the reasons that produced it and a "not checked" section.

### Outputs
- Markdown report, ready to paste into a ticket
- JSON with the full results
- Indicator search snippets for Splunk, Microsoft Sentinel (KQL) and Elastic, so an analyst can pivot immediately

## Milestones (build in this order, one at a time)

- **M1**: CLI skeleton, type identification, hashing, PE basics, strings and indicator extraction, Markdown and JSON report. Tests for each.
- **M2**: capa integration, YARA scanning, Office and LNK analyzers.
- **M3**: Archive and image handling with extraction limits, script and PDF analyzers, verdict rules.
- **M4**: Opt-in hash reputation lookups, SIEM search snippets.
- **M5**: Validation against real samples and a benign corpus (see "M5: Validation plan" below). No new analyzers in this milestone; only fixes for gaps the validation finds.

M1 to M4 are complete. M5 is next.

At the start of each milestone, plan first: propose structure, dependencies and tests, then wait for approval before writing code. Finish each milestone with passing tests and a commit.

## Tech choices

- Python 3.11+
- Candidate libraries (confirm each before adding): `pefile`, `oletools`, `flare-capa`, `yara-python`, `LnkParse3`, `python-magic` or equivalent, `py-tlsh`, `flare-floss` (optional; heavy)
- CLI with `argparse` or `typer`
- Tests with `pytest`
- Keep heavy or optional analyzers pluggable: if a library is missing, the report states that the analyzer was unavailable rather than crashing.

## Testing

- **Benign fixtures only** in the repo, built synthetically where possible: small PE files compiled from harmless source, Office files with harmless macros, crafted LNK and PDF files, archives for limit testing.
- The **EICAR test string** is acceptable as a known-detected benign file for YARA and reputation tests.
- Include a benign corpus test (ordinary installers and documents kept outside the repo) to measure false positives. A triage tool is only as good as its false-positive rate.
- Real malware testing happens only inside an isolated analysis VM (for example REMnux) with no shared folders or clipboard, using samples stored zipped with the password `infected`.

## M5: Validation plan

Goal: prove the tool is useful on real files, not only correct on synthetic fixtures, and publish the evidence in `docs/validation.md`.

### Who does what

- **Claude Code never downloads, unzips, handles or runs real samples.** It writes the harness, reads the text reports a person brings back, and fixes gaps using new synthetic fixtures.
- **A person runs the validation inside the analysis VM** (REMnux or FLARE-VM): host-only or no network, no shared folders, no shared clipboard, clean snapshot reverted after each session.
- Samples stay zipped with the password `infected` until analysis; `unopened` reads the zip directly (`infected` is the default archive password).
- Only text leaves the VM: the `.json` reports and the results CSV. Never a sample, an extracted member, or any dropped file.

### Sample sets

1. **Ground truth: Practical Malware Analysis labs** (also distributed in the RPISEC Malware course repository). The book's appendix walkthroughs describe what each sample does, which gives an expected answer. Start with the labs for chapters 1, 3, 5, 6, 7, 11, 12 and 13 (static basics, behavior, encoding, packing, covert launching). Kernel labs are out of scope.
2. **Current samples from MalwareBazaar**: about 30, chosen by tag to cover every supported type (PE, Office with macros, LNK, script, PDF, ISO and archive delivery). Record SHA256 and tags only.
3. **Benign corpus**, kept outside the repo and run through `UNOPENED_CORPUS`: ordinary installers, signed Microsoft binaries, Office documents with and without benign macros, PDFs, PowerShell admin scripts, and LNK files from a normal Start menu. At least 200 files.

### What to measure

- **Detection**: verdict counts on malicious samples. "No findings" on a known-malicious sample is a miss that needs an explanation.
- **Coverage against ground truth**: for each PMA lab, list the behaviors in the walkthrough and mark which the report surfaced (finding, capability or indicator), which it missed, and why.
- **False positives** on the benign corpus: malicious and suspicious verdicts, with the rule ID responsible. Target: no malicious verdicts, and suspicious on under 5% of files.
- **"Could not analyze" rate** and its causes: missing libraries, timeouts, unsupported formats.
- **Runtime**: median and worst case per file, with and without capa.

### Harness

- `scripts/validate.py` takes a directory of samples (or of zips) and an expectations CSV (`sha256,label,expected_verdict,expected_behaviors`), runs triage on each file with JSON output, and writes `validation-results.csv` plus a summary table. It prints counts and rule IDs only, never raw indicators.
- The PMA expectations CSV is written by hand from the walkthroughs and committed under `validation/`. It holds hashes and behavior labels only, no sample bytes.
- Every miss or false positive ends as one of: a fix with a synthetic regression test, a documented limitation in the README, or an entry under "Not checked".

### Done when

- `docs/validation.md` states the method, tool version, sample counts per type, the detection table, the false-positive table, each miss with its explanation, and runtime.
- Every fix made during validation has a synthetic regression test.
- The README links to `docs/validation.md`.

## Repository hygiene

- `.gitignore` must exclude `samples/`, `validation-results.csv`, `*.zip` outside `tests/fixtures/`, and any file not explicitly a fixture.
- No real sample, real customer document, or real indicator from an investigation is ever committed.

## Out of scope for version 1

- Dynamic analysis or sandboxing of any kind
- Machine-learning verdicts
- A web UI
- Automatic file submission to any third-party service
