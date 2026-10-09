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
| Current samples (holdout) | _not yet run_ | MalwareBazaar tags; samples the rules were not written against |

## Results: RPISEC labs

The run was repeated after each change, so the effect of every fix is visible.

| Run | Malicious | Suspicious | No findings | Expected verdict met | Behavior coverage |
|---|---|---|---|---|---|
| 1. First run | 3 | 14 | 0 | 16 of 16 | 76% |
| 2. Name inflation removed | 3 | 4 | 10 | 8 of 16 | 80% |
| 3. Behavior patterns added | 3 | 8 | 6 | **12 of 16** | **80%** |

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

## Results: benign corpus

201 files: the Sysinternals Suite (Microsoft-signed admin tools that read process memory,
adjust privileges and manage services by design), the Python 3.12 embeddable build, the
7-Zip 24.08 installer and PuTTY. The target was no malicious verdicts and suspicious on
fewer than 5% of files.

| Run | Malicious | Suspicious | False-positive rate |
|---|---|---|---|
| 1. After the RPISEC fixes and behavior patterns | 4 | 62 | **32.8%** (66 of 201) |
| 2. After the fixes below | _pending_ | _pending_ | _pending_ |

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

The dropper pattern stays at MEDIUM until run 2 shows how it behaves on the 7-Zip
installer.

## Runtime

RPISEC labs, run 3: median 36.5 s per zipped lab (three samples each, capa included),
slowest 85.3 s, 354 s in total.
