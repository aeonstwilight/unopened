# Contributing

Issues and pull requests are welcome.

- **Never attach or commit a sample**, not even zipped. Describe it by SHA256, or build a
  small synthetic file that reproduces the problem (see `tests/fixtures/`). Security
  problems go through private reporting: see [SECURITY.md](SECURITY.md).
- How the code fits together, and the steps for adding an analyzer:
  [docs/architecture.md](docs/architecture.md).
- The hard rules every change must keep (static only, defanged output, no network by
  default, bounded extraction, fail loudly) are in [CLAUDE.md](CLAUDE.md); tests enforce
  most of them.

Before opening a pull request:

```sh
pip install -e ".[all,dev]"
ruff check src tests
mypy
pytest
python -m unopened.verdict | diff - docs/verdict-rules.md   # after changing a verdict rule
```

A change that alters a verdict needs a synthetic regression test, and a new rule needs a
case in `tests/test_verdict.py`.
