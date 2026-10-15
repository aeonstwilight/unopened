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
| Benign corpus 1 | 201 files | Ordinary Windows software: Sysinternals Suite, the Python 3.12 embeddable build, the 7-Zip 24.08 installer, PuTTY |
| Benign corpus 2 | 146 files (plus their contents) | Everything corpus 1 lacked: Office files including five with macros written for the test, IRS fill-in PDFs, PowerShell Gallery modules, JavaScript libraries, Windows' own VBScript and batch files, Start-menu shortcuts, and installers fetched with winget |
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

## Results: holdout set 2 (MalwareBazaar)

A fresh set, because the first holdout shaped the fixes above and no longer measures
unseen malware. Picked the same way on October 14: the newest samples per file type.
Rules frozen at commit `cd45981`, after every fix in this document. Hashes and tags are
in `validation/holdout2-malwarebazaar.csv`. Two PDFs were also in set 1 (few new PDFs had
been uploaded in between); they are marked in the notes. One zip contained a second
sample that is also listed, so 30 downloads gave 31 scored samples.

**Run 1: expected verdict met on 8 of 31.** 7 malicious, 1 suspicious, 1 could not
analyze (a password-protected PDF, tag `pass`), 22 no findings. Without the two repeated
PDFs: 8 of 29.

That is lower than set 1's first run (11 of 30), on a different mix: set 2 has more
compiled programs and loaders, and the misses are mostly EXEs and DLLs.

**Regression check: did the corpus 2 fixes cost detection?** The same 31 samples were run
on the rules as they stood before the corpus 2 fixes (commit `5cc78aa`): **9 of 31**, one
more than the current rules. The other 30 results are identical, so the stricter script
and macro rules did not lose any of this set's scripts or Office files.

The one difference is a .NET RAT in a zip (`3b35d323…`). Under the old rules it had three
MEDIUM findings (V-SUS-04): a future compile timestamp, a high-entropy `.text` section,
and "capa results are limited for this file". Corpus 2 lowered that last one to INFO,
because it describes what capa could not see rather than anything found, and it helped
push signed installers into false positives. So the old rules caught this sample on a
weak signal. That change stays. The stronger evidence was in the same report and no rule
combined it: an unsigned .NET program with an encrypted-looking `.text` section (7.74 of
8.0) that loads and invokes a .NET assembly from a resource, the usual crypter shape. It
is a candidate for the set 2 fixes below.

**Fixes after run 1.** A probe (`scripts/probe_shapes.py`, which prints only counts, hash
prefixes and Office relationship types) measured the script and unrecognized members
before any rule was written, and changed several first guesses:

| Miss | What the probe showed | Fix |
|---|---|---|
| Two "PowerShell" scripts, name mismatch only | GuLoader VBScripts padded with comment lines full of PowerShell-looking words; scored as PowerShell and checked with the wrong rules | When the content also shows signs of the language the name says, the name decides |
| 8.6 MB RemcosRAT JScript, "unrecognized binary data" | 17% non-ASCII bytes, valid UTF-8: padding with zero-width and private-use characters, which the text check counted as binary | Only control codes count against text |
| RemcosRAT JScript, one line of 3,018,473 characters | ActiveX plus that line; LOW and MEDIUM only | A line over 500,000 characters is MEDIUM (jQuery, minified, is about 90,000); with COM objects, commands or Execute/Eval it is a HIGH pattern |
| AsyncRAT batch file, 880 KB | 783 `%var:~n,m%` substrings spelling every command, and a reference to its own path | Batch variables are expanded as text (as cmd.exe would, never run); 50+ substrings is obfuscation; obfuscated plus `%~f0` is a HIGH pattern |
| .NET RAT in a zip (`3b35d323…`) | See the regression check above | Unsigned .NET + MEDIUM-entropy code section + loads or invokes an assembly: HIGH pattern |
| Native loader | capa: resolve function by Brute Ratel Badger hash | Unsigned + capa "resolve function by … hash": HIGH pattern |
| ISO: Dropbox-signed EXE beside a DLL signed by an individual | The DLL allocates RWX memory, embeds a PE and calls shellcode | Cross-member check for DLL side-loading (HIGH) |
| Word document named `.doc` | Its only external relationship is an ordinary hyperlink | None: a lure link for the reader to click, not content that loads on open. Documented |

**Run 2, after these fixes: 18 of 31** (7 malicious, 11 suspicious). Every new
detection came from the fix meant for it. The benign corpora then showed one fix was too
broad: a pattern for VBScript that runs text it assembles (Execute or Eval plus Mid,
StrReverse or Chr) made `slmgr.vbs` and `winrm.vbs` suspicious. Five of winrm's matches
were `RegExp.Execute`, a method that runs a regular expression, and that keyword bug was
fixed. The rest were real: both scripts run Eval or Execute on a variable. The probe then
compared the two GuLoader samples with the two Microsoft scripts: Execute on a variable
in all four, similar Chr and Mid counts; only the share of comment lines differed (41%
and 69% against 4% and 6%). Four files are not enough to set a threshold on, so the
pattern was removed.

**Run 3, the final rules for this set (commit `1ed7743`): 16 of 31** (7 malicious, 9
suspicious, 1 could not analyze, 14 no findings). Without the two repeated PDFs: 16 of
29. These samples shaped the fixes, so this is a rerun, not a holdout result.

| Remaining misses | Count | Why |
|---|---|---|
| GuLoader VBScripts | 2 | Identified correctly and their Execute is reported (MEDIUM), but no rule turns it into a verdict without also flagging Microsoft's own scripts |
| .NET DLLs (RGBLoader) and a .NET program with an encrypted-looking code section but no assembly loading | 4 | Only LOW signals: HTTP, geolocation, screenshots, hidden windows, resource access. No combination specific enough to write from these samples |
| Native loaders | 3 | RC4 plus PE parsing (two), or writes and runs a file and references the Startup folder (one); each signal is common in installers |
| Macro workbooks | 2 | Macros plus suspicious functions (two MEDIUMs); no auto-run trigger was found |
| Lure documents | 3 | Two link-only PDFs (also in set 1) and a Word document whose only external link is a hyperlink |
| Password-protected PDF | 1 | Correctly "could not analyze": the password is not known |

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
| 4. After the corpus 2 and holdout set 2 fixes | 0 | 0 | **0.0%** (0 of 201), see below |

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

**Run 4, after the corpus 2 and holdout set 2 fixes (October 14–15): 0 of 201**, but
read it as 0.5%. ZoomIt64, the false positive in runs 2 and 3, came back clean only
because capa hit its 300-second limit on it (run 3: 295 s and suspicious; run 4: 306 s,
timed out, "no findings", with the timeout listed under not checked). When capa finishes,
the same three MEDIUM findings are expected. None of the holdout set 2 patterns or the
side-loading check fired on this corpus.

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

## Results: benign corpus 2

Built to cover what corpus 1 did not (October 12): 146 files. Office documents and
workbooks, including macro workbooks written for this test (formatting, a date stamp on
open, a CSV export with `FileSystemObject`, and one that creates a folder on open); 20 IRS
fill-in PDFs; five PowerShell Gallery packages, each holding dozens of scripts and
assemblies; jQuery, lodash, d3, moment and Bootstrap; the VBScript and batch files in a
Windows `System32` folder; about 40 Start-menu shortcuts; and installers for common
open-source tools downloaded with `winget`.

**Run 1 failed the target: 3 malicious, 4 suspicious (7 of 146, 4.8%).** Every one was
traced with `scripts/miss_details.py --all`:

| File | Verdict | Cause | Fix |
|---|---|---|---|
| `slmgr.vbs` (Microsoft) | malicious | Isolated `Chr()` calls counted as obfuscation, on top of real download and execute keywords | Obfuscation is judged by shape: runs of chained char codes or joined literals |
| `autolog.xlsm` (test workbook) | malicious | Auto-run plus `CreateObject`: the macro rule treated object creation like running programs | Malicious needs auto-run plus running programs, downloading or calling Windows; auto-run alone stays suspicious |
| `PSScriptAnalyzer.nupkg` | malicious | One member, `Settings/core-6.1.0-windows.json`, lists cmdlet names (`Invoke-WebRequest`, `Invoke-Expression`, `Start-Process`) and was identified as a PowerShell script by content | Text that opens like JSON is identified as JSON data before the script heuristics run |
| `jquery.js` | suspicious | `RegExp.exec(` matched "runs programs" (case was ignored), plus the obfuscation count | Case-sensitive method names; obfuscation by shape |
| `ImportExcel.nupkg` | suspicious | One member, `Examples/OutTabulator/start-demo.ps1`: obfuscated plus `Invoke-Expression` | Expected to clear with the obfuscation change; run 2 will show |
| Rufus, Firefox installers | suspicious | Three MEDIUM findings, mostly packing on validly signed files, plus "capa results are limited" | Packing on a validly signed PE is LOW; "capa results are limited" is INFO, since it describes what was not seen |

It also found two parser problems that a clean verdict had hidden:

- **Every IRS PDF was only partly analyzed.** An `/EF` entry holding an array raised an
  error that ended the walk through the document, so the forms' JavaScript was never
  seen. Fixed: the odd entry is skipped, and a failing object is reported while the walk
  continues. The W-4 now shows its three JavaScript blocks (field calculations) and
  still comes back "no findings".
- **17 shortcuts were partly analyzed.** Windows' own Start-menu shortcuts (Character Map
  among them) keep their target only in the environment-variable block
  (`%windir%\system32\charmap.exe`) or name a Windows Installer product instead of a path.
  Both are now read.

| Run | Malicious | Suspicious | False-positive rate |
|---|---|---|---|
| 1. First run | 3 | 4 | **4.8%** (7 of 146) |
| 2. After the fixes above | 1 | 1 | **1.4%** (2 of 146) |
| 3. After two more | 0 | 1 | **0.7%** (1 of 146) |
| 4. After the holdout set 2 fixes | 0 | 3 | **2.1%** (3 of 146) |
| 5. After removing the VBScript pattern | pending | pending | pending |

**Run 2** cleared five of the seven and both parser problems. `slmgr.vbs` was still
malicious, for two reasons found by printing its matching lines: it uses `ADODB.Stream`
to read and write files, which the rule counted as downloading, and its one run of char
codes, `Chr(239) + Chr(187) + Chr(191)`, builds the UTF-8 byte-order mark to check a file's
encoding. Fixes: only XMLHTTP and WinHttp count as downloading (`ADODB.Stream` is a LOW
file-writing finding), and a char-code run counts as obfuscation only if it spells visible
ASCII. A real fetch-save-run script still reaches "downloads and runs code"; both cases
have regression tests.

**Run 3 met the target**: no malicious verdicts and one suspicious file, the test
workbook that creates a folder when it opens. Its macro runs automatically on open, which
deserves a look, so it is left as found. In the other direction, these fixes make the
tool stricter about what counts as malicious; they were checked against the synthetic
malicious fixtures, and a holdout rerun against them is listed under what remains.

**Run 4, after the holdout set 2 fixes: 3 suspicious.** The macro workbook as before, and
`slmgr.vbs` and `winrm.vbs` through the VBScript pattern described under holdout set 2,
which was then removed. **Run 5** is in progress; its result will be recorded here.

The VM stalled twice during run 3 and killed the run while it was writing a row, which
exposed a harness bug: `--resume` failed on the cut-off line. Fixed, with a test; the run
was resumed and completed.

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

## What remains

- **A third holdout set.** Sets 1 and 2 both shaped fixes, so neither measures unseen
  malware any more. Set 2's first run (8 of 31) is the most recent honest number.
- **Compiled loaders.** Most remaining misses are .NET and native programs whose static
  signals are each common in legitimate software. Patterns for them need more samples
  than one set provides, checked against both benign corpora.
- **capa timeouts.** capa stopped at 300 s on 17 corpus 1 files in run 4, and the
  verdict on at least one (ZoomIt64) depends on whether it finishes. A longer limit for
  validation runs, or a cheaper capa configuration, would make runs repeatable.
- **Known limitations, documented rather than fixed:** link-only PDF lures and lure
  documents with only hyperlinks, MSI contents, macro workbooks without auto-run that use
  suspicious functions, VBScript loaders that hide code behind Execute, and large scripts
  whose only signal is a single `eval`.
