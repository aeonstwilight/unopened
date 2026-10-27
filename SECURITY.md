# Security policy

unopened reads hostile files by design, so a bug in how it parses them can be a
security issue. Reports are welcome.

## What counts as a vulnerability

- Anything that makes unopened **run, open or render** part of a sample, or load it as
  code, macros or scripts.
- Any **network access** without `--reputation`, or any lookup that sends more than a hash.
- **Escaping extraction limits**: a crafted archive, image, PDF or Office file that writes
  outside the private temporary directory, exceeds the depth, count, size or ratio limits,
  or exhausts memory or disk despite them.
- **Undefanged indicators** in Markdown or HTML output, or anything in the HTML report
  that runs a script or loads a remote resource.
- A crafted file that makes a check **fail silently**, so the report looks clean when a
  check did not run.
- A crash or hang on a crafted file is a bug; report it the same way if you are unsure.

## How to report

Use GitHub's **private vulnerability reporting** on this repository (Security tab →
Report a vulnerability). Please do not open a public issue for these.

**Never attach malware**, not even zipped. Describe the file instead: its SHA256, its
type, and where it is publicly available (for example MalwareBazaar). The best report
is a small synthetic file that reproduces the problem without being malicious; the
fixtures in `tests/fixtures/` show how those are built.

You can expect an acknowledgement within a week. Fixes land with a synthetic
regression test and a CHANGELOG entry.

## Supported versions

Only the latest release receives fixes.
