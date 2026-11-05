#!/usr/bin/env python3
"""Convert Synthea CSV output into the PHI Guard patient schema.

Synthea gives us realistic demographics (names, birth dates, addresses, 999-xx-xxxx
SSNs). It does not produce MRNs, health-plan member IDs or provider NPIs in the
format our services use, so those are generated deterministically from the
Synthea patient UUID. Synthea appends digits to names (e.g. "Maria123"); we strip
them so the names look like names to an NER model.

Usage:
    python scripts/synthea_import.py --csv-dir build/synthea/csv --limit 200 \
        --out app/sample-ehr/data/patients.json
"""
from __future__ import annotations

import argparse
import csv
import json
import random
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from generate_patients import AREA_CODES, CPT, ICD10, PLANS, make_npi  # noqa: E402

DIGITS = re.compile(r"\d+")


def clean(name: str) -> str:
    return DIGITS.sub("", name or "").strip() or "Unknown"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv-dir", required=True)
    ap.add_argument("--limit", type=int, default=200)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default="app/sample-ehr/data/patients.json")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    providers = [make_npi(rng) for _ in range(25)]
    path = Path(args.csv_dir) / "patients.csv"
    if not path.exists():
        sys.exit(f"Synthea patients.csv not found at {path}")

    patients = []
    with path.open(newline="") as fh:
        for i, row in enumerate(csv.DictReader(fh), start=1):
            if i > args.limit:
                break
            prng = random.Random(row["Id"])  # deterministic per Synthea patient
            first, last = clean(row.get("FIRST", "")), clean(row.get("LAST", ""))
            prefix, plan = prng.choice(PLANS)
            code, desc = prng.choice(CPT)
            patients.append({
                "id": i,
                "mrn": f"MRN-{prng.randint(1_000_000, 9_999_999)}",
                "first_name": first,
                "last_name": last,
                "dob": row.get("BIRTHDATE", "1970-01-01"),
                "sex": row.get("GENDER", "U"),
                "address": {
                    "line": row.get("ADDRESS", ""),
                    "city": row.get("CITY", ""),
                    "state": row.get("STATE", ""),
                    "zip": (row.get("ZIP") or "00000")[:5],
                },
                "phone": f"({prng.choice(AREA_CODES)}) 555-01{prng.randint(0, 99):02d}",
                "email": f"{first.lower()}.{last.lower()}{prng.randint(1, 99)}@example.org",
                "ssn": row.get("SSN") or f"999-{prng.randint(10, 99)}-{prng.randint(1000, 9999)}",
                "member_id": f"{prefix}{prng.randint(100_000_000, 999_999_999)}",
                "plan": plan,
                "pcp_npi": prng.choice(providers),
                "claims": [{
                    "claim_id": f"CLM-{i:04d}-1",
                    "service_date": "2025-06-01",
                    "cpt": code,
                    "description": desc,
                    "icd10": prng.choice(ICD10),
                    "billed_amount": round(prng.uniform(80, 1800), 2),
                    "rendering_npi": prng.choice(providers),
                }],
                "synthetic": True,
                "source": "synthea",
            })
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(patients, indent=2))
    print(f"converted {len(patients)} Synthea patients -> {out}")


if __name__ == "__main__":
    main()
