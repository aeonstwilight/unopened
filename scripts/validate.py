"""Validation harness entry point (milestone M5). See src/unopened/validation.py.

Run inside the analysis VM only:

    python scripts/validate.py ~/samples/pma --expectations validation/pma-labs.csv \
        -- --capa-rules ~/rules/capa --yara-rules ~/rules/yara
    python scripts/validate.py ~/corpus --label benign
"""

from unopened.validation import main

if __name__ == "__main__":
    raise SystemExit(main())
