#!/usr/bin/env python3
"""Time yourself reviewing 10 findings: 5 with raw scanner output only, 5 with the triage output.

    python scripts/review_eval.py --reviewer "your name"

For each finding the clock starts when it is shown and stops when you press Enter
after deciding (a) why it matters and (b) what the fix is. You then self-rate
whether your fix was correct (check against the control's remediation).
Condition assignment is randomised and balanced; order alternates so learning
effects don't all land on one condition. Results go to evidence/review_times.json
and are summarised by `scripts/measure.py review`.

This is a single-reviewer, n=10 study. Report it as indicative, not significant.
"""
from __future__ import annotations

import argparse
import json
import random
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def show_manual(f: dict) -> None:
    print(f"  control   : {f['control_id']}  ({f['severity']})")
    print(f"  resource  : {f['resource']}")
    print(f"  location  : {f['file']}:{f['line']}")
    print(f"  message   : {f['message']}")
    print("  (no explanation, citation or fix provided: look things up as you normally would)")


def show_assisted(f: dict, t: dict) -> None:
    show_manual(f)
    print(f"  citation  : {t['hipaa_citation']}")
    print(f"  summary   : {t['risk_summary']}")
    print("  suggested fix:")
    for line in t["suggested_fix"]["diff"].splitlines():
        print(f"      {line}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--triage", default="evidence/triage.json")
    ap.add_argument("--reviewer", default="anonymous")
    ap.add_argument("--n", type=int, default=10)
    ap.add_argument("--seed", type=int, default=11)
    args = ap.parse_args()

    triage = json.loads((ROOT / args.triage).read_text())
    items = triage["items"]
    rng = random.Random(args.seed)
    picks = rng.sample(items, min(args.n, len(items)))
    conditions = ["manual", "assisted"] * (len(picks) // 2) + (["manual"] if len(picks) % 2 else [])
    rng.shuffle(conditions)

    print(__doc__)
    input("Press Enter to start...")
    results = []
    for i, (item, cond) in enumerate(zip(picks, conditions), start=1):
        print("\n" + "=" * 78 + f"\nFinding {i}/{len(picks)}  [{cond.upper()}]\n" + "=" * 78)
        (show_assisted(item["finding"], item["triage"]) if cond == "assisted" else show_manual(item["finding"]))
        t0 = time.monotonic()
        input("\nPress Enter when you know why it matters and how to fix it... ")
        secs = round(time.monotonic() - t0, 1)
        ok = input("Was your fix correct? Compare with policies/mapping.yaml remediation [y/n]: ").strip().lower() == "y"
        results.append({"finding_id": item["finding"]["finding_id"], "control_id": item["finding"]["control_id"],
                        "condition": cond, "seconds": secs, "fix_correct": ok})
        print(f"  recorded {secs}s")

    out = ROOT / "evidence" / "review_times.json"
    out.write_text(json.dumps({"reviewer": args.reviewer, "recorded_at": datetime.now(timezone.utc).isoformat(),
                               "provider": triage.get("provider"), "model": triage.get("model"),
                               "items": results}, indent=2))
    print(f"\nsaved {out.relative_to(ROOT)}; run `python scripts/measure.py review`")


if __name__ == "__main__":
    main()
