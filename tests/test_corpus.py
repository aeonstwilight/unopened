"""False-positive measurement over a benign corpus kept outside the repository.

    UNOPENED_CORPUS=/path/to/benign/files pytest -m corpus -s

Optional: UNOPENED_CORPUS_MAX_FLAGGED=0.05 fails the run if more than 5% of files get a
"malicious" or "suspicious" verdict (the false-positive rate that matters to an analyst).
Corpus files are ordinary installers and documents, never malware; they are read, never
executed.
"""

from __future__ import annotations

import os
from collections import Counter
from pathlib import Path

import pytest

from unopened import pipeline
from unopened.analyzers import Options
from unopened.indicators.allowlist import Allowlist
from unopened.model import Severity, Status

CORPUS = os.environ.get("UNOPENED_CORPUS")
MAX_FILES = int(os.environ.get("UNOPENED_CORPUS_LIMIT", "2000"))


@pytest.mark.corpus
@pytest.mark.skipif(not CORPUS, reason="set UNOPENED_CORPUS to a directory of benign files")
def test_benign_corpus_false_positive_rate():
    files = [p for p in sorted(Path(CORPUS).rglob("*")) if p.is_file()][:MAX_FILES]
    assert files, f"no files under {CORPUS}"
    options = Options(allowlist=Allowlist.load(), timeout=120)
    flagged: list[tuple[str, str]] = []
    failures: list[str] = []
    titles: Counter[str] = Counter()
    verdicts: Counter[str] = Counter()
    rules: Counter[str] = Counter()
    for path in files:
        report = pipeline.triage(path, options)
        for r in report.results:
            if r.status in (Status.ERROR, Status.TIMEOUT):
                failures.append(f"{path}: {r.name} {r.status}: {r.message}")
        titles.update(f.id for f in report.findings()
                      if f.severity in (Severity.HIGH, Severity.MEDIUM))
        verdicts[report.verdict["value"]] += 1
        rules[report.verdict["rule"]] += 1
        if report.verdict["value"] in ("malicious", "suspicious"):
            flagged.append((str(path), report.verdict["rule"]))

    rate = len(flagged) / len(files)
    print(f"\nbenign corpus: {len(files)} files, {len(flagged)} judged malicious or "
          f"suspicious ({rate:.1%}), {len(failures)} analyzer failures")
    print("  verdicts: " + ", ".join(f"{v} {n}" for v, n in verdicts.most_common()))
    print("  deciding rules: " + ", ".join(f"{r} {n}" for r, n in rules.most_common()))
    print("  most common MEDIUM/HIGH findings:")
    for title, n in titles.most_common(20):
        print(f"  {n:5d}  {title}")
    for path, rule in flagged[:30]:
        print(f"  FLAGGED {rule}  {path}")
    for f in failures[:20]:
        print(f"  FAIL {f}")
    limit = os.environ.get("UNOPENED_CORPUS_MAX_FLAGGED")
    if limit is not None:
        assert rate <= float(limit), f"false-positive rate {rate:.1%} exceeds {float(limit):.1%}"
    assert not failures, f"{len(failures)} analyzer failures on benign files"
