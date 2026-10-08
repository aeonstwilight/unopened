# Verdict rules

<!-- Generated from src/unopened/verdict.py by `python -m unopened.verdict`. Do not edit by hand; tests/test_verdict.py checks it is in sync. -->

Rules are checked in order. The first rule that matches sets the verdict and its confidence; every rule that matches is listed as a reason in the report, with the findings that triggered it.

Verdicts, most to least severe: **malicious**, **suspicious**, **could not analyze**, **no findings**. "No findings" only means that the checks that ran found nothing at MEDIUM or above; it never means the file is safe.

| Rule | Verdict | Confidence | When it matches |
|---|---|---|---|
| V-MAL-01 | malicious | high | A configured YARA rule with severity high (or score 75 and above) matched. |
| V-REP-01 | malicious | high | MalwareBazaar (a database of known malware samples) has this exact hash. Needs --reputation. |
| V-REP-02 | malicious | high | VirusTotal reports 5 or more engines detecting this hash as malicious. Needs --reputation and VT_API_KEY. |
| V-MAL-02 | malicious | high | Office macros run automatically on open and use functions that run programs, download files or create objects. |
| V-MAL-03 | malicious | high | A shortcut launches a scripting or download tool (LOLBin) with an encoded, hidden, padded or URL-bearing command, or carries an appended program. |
| V-MAL-04 | malicious | high | A document contains a DDE field that can run a command. |
| V-MAL-05 | malicious | high | A document loads a remote template or object when opened (template injection). |
| V-MAL-06 | malicious | high | A document or PDF embeds a file with an executable extension. |
| V-MAL-07 | malicious | high | A script (or PDF JavaScript) both downloads content and runs code, after deobfuscation. |
| V-MAL-08 | malicious | high | A PDF contains a Launch action that can start a program. |
| V-MAL-09 | malicious | medium | A member of this archive, disk image or PDF was judged malicious. |
| V-MAL-10 | malicious | medium | Two or more HIGH findings from different analyzers. |
| V-SUS-01 | suspicious | medium | At least one HIGH finding. |
| V-SUS-02 | suspicious | medium | A member of this archive, disk image or PDF was judged suspicious. |
| V-REP-03 | suspicious | low | VirusTotal reports between 1 and 4 engines detecting this hash as malicious (few detections are often false positives). |
| V-SUS-03 | suspicious | medium | An obfuscated script that also runs programs or code. |
| V-SUS-04 | suspicious | low | Three or more MEDIUM findings. |
| V-CNA-01 | could not analyze | high | The analyzer for this file type failed, timed out or is not installed, so the file was not really examined. |
| V-CNA-02 | could not analyze | high | Encrypted content could not be opened with the configured passwords. |
| V-CNA-03 | could not analyze | high | None of the archive's members could be extracted (limits, encryption or damage). |
| V-CNA-04 | could not analyze | medium | A member of this archive, disk image or PDF could not be analyzed. |
| V-NF-01 | no findings | medium | No rule above matched: nothing at MEDIUM or above, or not enough to call it suspicious. This is not a statement that the file is safe. |

## Confidence adjustments

- **No findings** drops to *low* confidence when any analyzer was partial, failed, timed out or was unavailable, when YARA did not run (no rules configured), when capa did not run on a PE file, when a member could not be analyzed, or when the file is empty.
- With `--reputation`, **no findings** also drops to *low* when no reputation source answered. A hash that no source knows is unknown, never clean, and never changes the verdict.
- **Malicious** and **suspicious** keep their confidence when other checks are incomplete (the evidence found still stands) but the report notes the gaps.
- Archives, disk images and PDFs take the most severe verdict among their own findings and their members (V-MAL-09, V-SUS-02, V-CNA-04).

Finding IDs used by these rules (for example `office.autoexec`) are stable and appear in the JSON report next to every finding.
