"""Print what the tool saw on each miss, for validation diagnostics.

For each saved report in DIR (validate.py --keep-reports) whose verdict is "no findings"
or "could not analyze": file type, verdict and rule, analyzers that did not finish, every
finding at every severity, capa capability names, why archive members were skipped, and
indicator counts by kind. Indicator values and member names are never printed, so the
output is safe to copy out of the analysis VM.

    python3 scripts/miss_details.py ~/validation-results/holdout-diag/reports
"""

from __future__ import annotations

import collections
import json
import sys
from pathlib import Path
from typing import Any

MISSES = ("no findings", "could not analyze")


def show(r: dict[str, Any], pad: str = "") -> None:
    ft = r.get("identification") or {}
    v = r.get("verdict") or {}
    print(f"{pad}[{ft.get('kind')}] {str(ft.get('description', ''))[:60]} -> "
          f"{v.get('value')} ({v.get('rule')}) size={r['file']['size']}")
    analyzers = r.get("analyzers", {})
    for name, a in analyzers.items():
        if a.get("status") not in ("ok", "not_applicable"):
            print(f"{pad}  ! {name}: {a.get('status')} {str(a.get('message', ''))[:90]}")
    for f in r.get("findings", []):
        print(f"{pad}  {f['severity'].upper():6} {f['id']}: {f['title'][:80]}")
    caps = (analyzers.get("capa", {}).get("data") or {}).get("capabilities") or []
    if caps:
        print(f"{pad}  capa: " + "; ".join(sorted(c["name"] for c in caps))[:600])
    for source in ("archive", "pdf"):
        members = (analyzers.get(source, {}).get("data") or {}).get("members") or []
        reasons = collections.Counter(m["skipped"] for m in members if m.get("skipped"))
        for reason, n in sorted(reasons.items()):
            print(f"{pad}  skipped {n} member(s): {str(reason)[:100]}")
    kinds = collections.Counter(i.get("type") for i in r.get("indicators", []))
    if kinds:
        print(f"{pad}  indicators (counts only): "
              + ", ".join(f"{k}={c}" for k, c in sorted(kinds.items())))
    for m in r.get("members", []):
        show(m["report"], pad + "    ")


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    for path in sorted(Path(argv[0]).rglob("*.json")):
        report = json.loads(path.read_text(encoding="utf-8"))
        if (report.get("verdict") or {}).get("value") in MISSES:
            print("=" * 70)
            print(report["hashes"].get("sha256", "")[:16], report["file"]["size"])
            show(report)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
