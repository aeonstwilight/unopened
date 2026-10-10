"""Print the verdict-relevant parts of saved JSON reports (validation diagnostics).

For each report in DIR (written by validate.py --keep-reports): verdict, signature status,
every HIGH and MEDIUM finding, and YARA rule names. No indicator values are printed.

    python scripts/report_findings.py ~/vr-diag/reports
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def signer(sig: dict) -> str:
    for s in sig.get("signers") or []:
        if isinstance(s, dict):
            return str(s.get("subject") or s.get("name") or s)[:60]
        return str(s)[:60]
    return ""


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(__doc__.strip().splitlines()[-1].strip(), file=sys.stderr)
        return 2
    files = sorted(Path(argv[0]).expanduser().glob("*.json"))
    if not files:
        print(f"no JSON reports in {argv[0]}", file=sys.stderr)
        return 2
    for f in files:
        r = json.loads(f.read_text(encoding="utf-8"))
        a = r["analyzers"]
        sig = (a.get("authenticode") or {}).get("data") or {}
        v = r["verdict"]
        print(f"== {r['file']['raw']['name']} | {v['value']} ({v['rule']}) | "
              f"signed={sig.get('signed')} valid={sig.get('valid')} {signer(sig)}")
        for x in sorted(r["findings"], key=lambda x: (x["severity"] != "high", x["id"])):
            if x["severity"] in ("high", "medium"):
                print(f"   {x['severity']:6} {x['id']}  ({x['title'][:70]})")
        for m in ((a.get("yara") or {}).get("data") or {}).get("matches", []):
            meta = m.get("meta") or {}
            print(f"   yara: {m.get('namespace', '')} {m.get('rule')} "
                  f"score={meta.get('score', '')} severity={meta.get('severity', '')}")
        slow = sorted(((n, x.get("duration_seconds", 0)) for n, x in a.items()),
                      key=lambda t: -t[1])[:2]
        print("   slowest: " + ", ".join(f"{n} {s:.0f}s" for n, s in slow))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
