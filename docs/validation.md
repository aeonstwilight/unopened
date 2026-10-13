# Validation

How unopened performs on real files, measured with `scripts/validate.py` (milestone M5).
Every number below comes from a run of that script; the method is described first so the
numbers can be reproduced and challenged.

## Method

- **Where it ran.** A REMnux virtual machine with no network during triage, no shared
  folders, and snapshots taken before each run. Samples stayed zipped with the password
  `infected`; unopened reads the zip directly. Nothing was executed.
- **What left the VM.** Only the text summaries and result tables, which carry verdicts,
  rule IDs, finding IDs and behavior labels. No sample, extracted file or raw indicator.
- **Tool configuration.** unopened 0.1.0 with every optional analyzer installed: capa 9.4.0
  with the matching capa-rules release and FLIRT signatures, the YARA Forge "core" rule
  set, TLSH, and Authenticode verification. Default limits and timeouts.
- **Scoring.** Each malicious sample has an expected verdict and a list of behaviors taken
  from its published write-up (see the expectations CSVs in `validation/`). A behavior
  counts as surfaced when the report shows it as a finding, a capa capability, an import
  category or an indicator. The mapping is in `src/unopened/validation.py` (`BEHAVIORS`).

## Sample sets

| Set | Files | Ground truth |
|---|---|---|
| RPISEC Malware course labs | 17 PE samples in 9 zipped labs | Each lab's `solution.md` ([RPISEC/Malware](https://github.com/RPISEC/Malware), credited in `validation/rpisec-labs.csv`) |
| Benign corpus | 201 files | Ordinary Windows software: Sysinternals Suite, the Python 3.12 embeddable build, the 7-Zip 24.08 installer, PuTTY |
| Current samples (holdout) | 30 MalwareBazaar samples, 13 file types | MalwareBazaar tags; samples the rules were not written against |

## Results: RPISEC labs

The run was repeated after each change, so the effect of every fix is visible.

| Run | Malicious | Suspicious | No findings | Expected verdict met | Behavior coverage |
|---|---|---|---|---|---|
| 1. First run | 3 | 14 | 0 | 16 of 16 | 76% |
| 2. Name inflation removed | 3 | 4 | 10 | 8 of 16 | 80% |
| 3. Behavior patterns added | 3 | 8 | 6 | **12 of 16** | **80%** |
| 4. After the benign-corpus fixes | 3 | 8 | 6 | **12 of 16** | **80%** |

**Run 1 looked better than it was.** Fourteen "suspicious" verdicts rested mostly on one
finding: the samples are stored as `*.malware`, and a program whose extension doesn't
match its content was rated HIGH. A storage name is not a disguise, so that finding is now
LOW unless the extension claims a harmless type such as a document or image.

**Run 2 was the honest baseline.** Ten known-malicious samples came back "no findings",
yet behavior coverage rose to 80%: the analyzers saw what the samples do (capa named
"create reverse shell" on one of them), but the verdict counted only individual HIGH or
MEDIUM findings, and most real signals are LOW on their own.

**Run 3 added behavior patterns** (`src/unopened/data/behaviors.toml`): named
combinations such as "enumerates files and sends files over HTTP, unsigned". Four samples
moved to suspicious: a reverse shell, a file stealer, a shellcode-style loader and a
sample hiding its strings and API calls.

**Run 4 repeated the labs after the benign-corpus fixes** (quieter capa tactic summaries,
unsigned-only keystroke and reverse-shell patterns, post-quantum signature handling, the
signed-file YARA cap). Every verdict and every behavior result matched run 3, so the fixes
that removed 65 false positives cost no detection on these samples.

### Remaining misses

| Sample | Verdict | Why |
|---|---|---|
| Lab_03-1, Lab_05-1, Lab_05-2 | no findings | Droppers. The "drops an embedded program" pattern matches all three but is held at MEDIUM until the benign run shows unsigned installers don't trip it. The finding is in each report. |
| Lab_08-1 | no findings | Its evasion is anti-disassembly and timing checks, invisible to static analysis; its persistence path is built at run time. |
| Lab_04-2 | no findings (accepted) | A crackme; the zipped build is not packed, and there is little to flag statically. |

Behaviors that static analysis cannot see in these samples, and why, are listed in the
notes column of `validation/rpisec-labs.csv`: APIs resolved at run time, strings built at
run time, and payloads that live inside an embedded program the tool lists but does not
yet analyze.

### Caveat

The behavior patterns were written while looking at these 17 samples, so run 3 is
optimistic by construction. The benign corpus measures false positives, and the holdout
set measures detection on samples the rules have never seen. Both belong next to these
numbers.

## Results: holdout (MalwareBazaar)

The most honest number in this document. Thirty current samples, the newest on
MalwareBazaar for each file type at the time of download (October 2026), picked by type and
date rather than by how the tool did on them. The rules were frozen at commit `0c57e61`
before the run, and nothing was tuned until this first result was recorded. Hashes and tags
are in `validation/holdout-malwarebazaar.csv`. One sample, a 7z, is locked with a password
named in its tags (5733); an analyst would have it from the delivery email, so it was
passed with `--archive-password`.

**Run 1: expected verdict met on 11 of 30.** 4 malicious, 7 suspicious, 1 could not
analyze, 18 no findings.

| Type | Met | Type | Met |
|---|---|---|---|
| LNK | 4 of 4 | Scripts (ps1, js, bat, vbs) | 1 of 6 |
| Office .doc | 2 of 2 | PDF | 0 of 3 |
| DLL | 2 of 3 | ZIP | 0 of 2 |
| EXE | 1 of 5 | ISO | 1 of 2 |
| Office .xls | 0 of 2 | 7z | 0 of 1 (could not analyze) |

The gap between this and the RPISEC result (12 of 16) is the gap between rules written
while looking at the samples and rules meeting samples they have never seen.

### The 19 misses

Read from the saved reports with `scripts/miss_details.py`, which prints findings,
capabilities and indicator counts but no indicator values.

| Misses | What the report showed | Outcome |
|---|---|---|
| 3 scripts | Junk padding at the start hid the language, so they were identified as plain text and the script analyzer never ran | **Fixed**: text with a script extension is treated as that script (`tests/test_identify.py`) |
| 1 PowerShell script | Obfuscated, and sets up a scheduled task or Run key: two MEDIUM findings, one short of suspicious | **Fixed**: new pattern, obfuscated script that sets up persistence |
| 3 EXEs (Vidar) | Process-injection imports and a signature from an untrusted certificate; capa timed out | **Fixed**: new pattern, and a signature that fails verification no longer mutes unsigned-only patterns |
| 1 DLL (WannaCry) | Embedded program, the dropper pattern and a YARA match, each MEDIUM | **Fixed**: new pattern, embedded program with a YARA match |
| 1 ISO | 12 programs and 16 hidden files: Microsoft-signed DLLs beside a DLL from an untrusted signer that bypasses UAC | **Fixed**: new patterns for the image layout and the UAC bypass; reproducible-build timestamps on the signed DLLs no longer count as forged |
| 1 tiny EXE | One import, walks the PEB, stack strings, resolves functions from exports | **Fixed**: the shellcode and hidden-API patterns now accept an almost empty import table and export parsing |
| 2 MSI installers | No findings, and the report did not say MSI contents go unexamined | **Fixed (reporting)**: listed under Not checked, confidence low. MSI analysis itself is out of scope for version 1 |
| 2 Excel .xls | VBA macros using suspicious functions, no auto-run trigger | **Open**: legitimate macro workbooks use the same functions; needs the second benign corpus, which has macro documents, before any rule |
| 3 PDFs | Links only, no JavaScript, actions or attachments | **Limitation**: a link-only lure looks like an ordinary document to static analysis. The links are in the indicators for pivoting |
| 1 JavaScript | Only a LOW `eval` finding on a large file | **Limitation** for now: the deobfuscator handles base64, char codes and concatenation, not this |
| 1 7z | A 15 MB archive declaring a single 961 MB program (file pumping, padding to get past scanner size limits); refused by the per-member limit and reported only as could not analyze | **Fixed**: a program declared past the limit at 20 times or more its compressed size is a HIGH finding, since the padding is itself the evidence |

**Run 2, after the fixes: expected verdict met on 21 of 30** (4 malicious, 17 suspicious,
0 could not analyze, 9 no findings). The nine left are the ones the table above leaves
open or documents: the three link-only PDFs, the two MSI installers (now reported as not
examined), the two macro workbooks, and two scripts (a batch file and a JavaScript file)
that are now analyzed as scripts but show nothing that reaches the threshold.

Read run 2 with two cautions. These samples shaped the fixes, so it measures whether the
fixes do what they were written to do, not how the tool does on new malware; that takes a
fresh holdout set. And the new patterns have not yet been run against the benign corpus,
so their false-positive cost is unmeasured until they are.

Each fix has a synthetic regression test (`tests/test_holdout_fixes.py`,
`tests/test_behaviors.py`, `tests/test_pe.py`). Run 2 will be reported next to run 1, not
in its place, and it is no longer a holdout: these samples shaped the fixes. A fresh
holdout set is the honest check of them. The fixes were checked against the benign corpus
in run 3 below: no new false positives.

Runtime: median 7.2 s per file, slowest 908 s (an ISO stopped by the 900-second file
budget, its first real use), 50 minutes in total. capa timed out on 4 files.

## Results: benign corpus

201 files: the Sysinternals Suite (Microsoft-signed admin tools that read process memory,
adjust privileges and manage services by design), the Python 3.12 embeddable build, the
7-Zip 24.08 installer and PuTTY. The target was no malicious verdicts and suspicious on
fewer than 5% of files.

| Run | Malicious | Suspicious | False-positive rate |
|---|---|---|---|
| 1. After the RPISEC fixes and behavior patterns | 4 | 62 | **32.8%** (66 of 201) |
| 2. After the fixes below | 0 | 1 | **0.5%** (1 of 201) |
| 3. After the holdout fixes (new patterns, failed-signature rule, script and OPC identification, time budget) | 0 | 1 | **0.5%** (1 of 201) |

**Run 1 failed the target badly.** Diagnostics on 13 representative files found four
causes:

1. **Post-quantum signatures broke signature checking.** Every Microsoft-signed file in
   the corpus includes a certificate with an ML-DSA-87 public key. The ASN.1 library under
   signify maps key types through a fixed table, raised `KeyError` on the unknown
   identifier, and the whole file was reported as "signature failed verification"
   (MEDIUM), so the strongest evidence of legitimacy turned into evidence against it.
   `src/unopened/asn1_compat.py` now registers the ML-DSA and SLH-DSA identifiers so the
   RSA signature beside them verifies; PsExec, BgInfo and PuTTY then verified as OK.
2. **capa's ATT&CK tactic summaries were MEDIUM.** Defense Evasion, Persistence and
   Privilege Escalation summaries appeared on nearly every admin tool, and three MEDIUM
   findings make a file suspicious (V-SUS-04). They are LOW now; specific capabilities
   carry weight through behavior patterns instead.
3. **Two behavior patterns fired on signed tools.** "Keystroke logging" matched TCPView,
   VMMap and Autoruns (GUI programs check key state for hotkeys) and "Reverse shell"
   matched PuTTY, a remote shell client by design. Both now require an unsigned file; on
   a signed file the evidence is still shown, at LOW.
4. **YARA rules matched signed Microsoft tools at score 75**, which made them malicious:
   an auto-generated Snake rule on BgInfo, a RisePro rule on handle.exe, and a rule that
   detects .NET single-file bundles on RDCMan. A lone HIGH YARA match on a file with a
   valid signature is now MEDIUM, with a note that certificates can be stolen.

**Run 3 repeated the corpus after the holdout fixes** (October 12, corpus rebuilt from the
same sources: the Sysinternals Suite as published that day, the Python 3.12.7 embeddable
build, 7-Zip 24.08, PuTTY). Same result: 0 malicious, 1 suspicious, the same ZoomIt64. The
six new behavior patterns and the rule that a failed signature lends no trust added no false
positives here. The slowest file took 901 s, inside the 900-second file budget plus the
cleanup after it, where run 2's slowest took 1,356 s. The run was interrupted once by a
crash of the Python process (a bus error, with disk and memory to spare) after 187 files
and resumed with `--resume`; the remaining files completed normally, including the one it
was working on.

**Run 2 met the target**: no malicious verdicts and one suspicious file. The remaining
false positive is ZoomIt64, where three MEDIUM heuristics stack up (V-SUS-04). It is left
as found rather than tuned away.

Read this number with three limits in mind:

- **The fixes were made against this corpus**, so run 2 is optimistic in the same way the
  RPISEC numbers are. A second, different benign set is needed before it is a general
  claim.
- **capa hit its 5-minute limit on 15 files**, so behavior patterns that rely on capa
  could not fire there. The true rate on those files is unmeasured, not zero.
- **The corpus is mostly signed Windows tools.** It has one unsigned installer (7-Zip),
  no documents, scripts or shortcuts. The dropper pattern stays at MEDIUM: one unsigned
  installer is not enough evidence to promote it.

## Runtime

- RPISEC labs, run 4: median 45.7 s per zipped lab (up to three samples each, capa
  included), slowest 94.4 s.
- Benign corpus, run 2 (2 parallel jobs in a 2-CPU VM): median 72.9 s per file, 6.5 hours
  of analysis in total. capa accounts for nearly all of it and hit its 5-minute limit on 15
  files.
- **Overrun, fixed:** the slowest benign file took 1,356 s, past every per-analyzer limit
  (capa 300 s, others 60 s). The limits were working; nothing capped the file as a whole.
  Analyzers run one after another, so a single PE could take up to 660 s, and every
  archive member got a fresh set of limits, so an archive had no ceiling at all. 1,356 s
  is more than one PE can take, which points to an archive in the corpus. There is now a
  time budget for the whole file (`--file-timeout`, default 900 s): each analyzer gets the
  smaller of its own limit and the time left, and analyzers or members still pending when
  it runs out are listed under Not checked, with the verdict's confidence lowered to low.
  Regression tests: `tests/test_time_budget.py`.
