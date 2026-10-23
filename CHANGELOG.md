# Changelog

Milestones are defined in `CLAUDE.md`. Each was planned, approved and merged as its own
pull request.

## M6: hardening without the analysis VM

- **CI**: GitHub Actions runs `ruff`, the test suite and a check that
  `docs/verdict-rules.md` matches the rules, on Python 3.11 and 3.13, with every optional
  analyzer installed.
- **capa**: the parsed rule set is reused from capa's on-disk cache (it was written but
  never read back), and a run that times out falls back to file-level rules only. The
  report then marks capa PARTIAL and lists function-level capabilities under Not checked.
  Analyzers can declare such a fallback in general; a fallback never reports OK.
- **FLOSS** (optional `floss` extra): decoded, stack and tight strings for PE files,
  recovered by emulation in vivisect like capa. Shown in the report and searched for
  indicators, but kept out of the verdict until a benign-corpus rerun.
- The validation harness labels capa fallbacks `capa:timeout-fallback`.

## M5: validation on real samples

RPISEC course labs, two MalwareBazaar holdout sets and two benign corpora, run in an
isolated VM. Behavior patterns, many detection and false-positive fixes, each with a
synthetic regression test. Results and method in `docs/validation.md`.

## M4: reputation and hunt queries

Opt-in hash-only lookups at MalwareBazaar and VirusTotal (`--reputation`), and hunt
queries for Splunk, Microsoft Sentinel / Defender and Elastic.

## M3: archives, scripts, PDF, verdicts

Bounded recursive extraction of ZIP, 7z and ISO; text-only script deobfuscation; PDF
JavaScript, actions and attachments; documented verdict rules.

## M2: capa, YARA, Office, LNK

capa capabilities with ATT&CK mapping, YARA with user rules, Office macro and
template-injection analysis, shortcut analysis.

## M1: the tool

CLI, type identification by content, hashes, PE basics, Authenticode, strings and
indicators, defanged Markdown and JSON reports.
