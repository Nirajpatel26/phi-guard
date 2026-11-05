#!/usr/bin/env python3
"""Generate a reproducible synthetic patient population for PHI Guard.

Pure standard library (no Faker) so it runs anywhere Python 3.11 runs.
Every identifier is synthetic by construction:

* SSN-like values use area numbers 900-999, which the SSA never issues as SSNs
  (Synthea uses the same trick with 999-xx-xxxx).
* Phone numbers use the 555-0100..0199 block reserved for fiction.
* Emails use example.com / example.org (RFC 2606 reserved domains).
* NPIs are 10 digits with a valid Luhn check digit over the 80840 prefix, so
  they exercise the NPI validator, but they are randomly generated.

Usage:
    python scripts/generate_patients.py --count 200 --seed 42 --out app/sample-ehr/data/patients.json
"""
from __future__ import annotations

import argparse
import json
import random
from datetime import date, timedelta
from pathlib import Path

FIRST_NAMES = [
    "James", "Mary", "Robert", "Patricia", "John", "Jennifer", "Michael", "Linda",
    "David", "Elizabeth", "William", "Barbara", "Richard", "Susan", "Joseph", "Jessica",
    "Thomas", "Sarah", "Charles", "Karen", "Christopher", "Lisa", "Daniel", "Nancy",
    "Matthew", "Betty", "Anthony", "Margaret", "Mark", "Sandra", "Donald", "Ashley",
    "Steven", "Kimberly", "Paul", "Emily", "Andrew", "Donna", "Joshua", "Michelle",
    "Priya", "Arjun", "Mei", "Wei", "Carlos", "Sofia", "Fatima", "Omar", "Aisha", "Hiro",
]
LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
    "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson",
    "Thomas", "Taylor", "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson",
    "White", "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson", "Walker",
    "Young", "Allen", "King", "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores",
    "Patel", "Shah", "Chen", "Wang", "Kim", "Singh", "Khan", "Tanaka", "Okafor", "Cohen",
]
STREETS = ["Maple", "Oak", "Cedar", "Elm", "Pine", "Birch", "Willow", "Harbor", "Summit", "Lake"]
STREET_TYPES = ["St", "Ave", "Rd", "Ln", "Dr", "Ct"]
CITIES = [("Boston", "MA", "021"), ("Worcester", "MA", "016"), ("Springfield", "MA", "011"),
          ("Hartford", "CT", "061"), ("Providence", "RI", "029"), ("Albany", "NY", "122")]
AREA_CODES = ["617", "508", "413", "860", "401", "518"]
PLANS = [("HPX", "Harborview Health PPO"), ("BCN", "Bay Coast Network HMO"),
         ("MNC", "Minuteman Care EPO"), ("GSH", "Granite State Health")]
CPT = [("99213", "Office visit, est. patient"), ("99214", "Office visit, moderate"),
       ("80053", "Comprehensive metabolic panel"), ("85025", "CBC with differential"),
       ("93000", "Electrocardiogram"), ("71046", "Chest X-ray, 2 views")]
ICD10 = ["E11.9", "I10", "J45.909", "M54.5", "E78.5", "F41.1", "K21.9", "N39.0"]


def npi_check_digit(first9: str) -> int:
    """Luhn check digit for an NPI, computed over '80840' + first 9 digits."""
    digits = [int(c) for c in "80840" + first9]
    total = 0
    # Double every second digit from the right of the payload (check digit excluded).
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return (10 - total % 10) % 10


def make_npi(rng: random.Random) -> str:
    first9 = str(rng.choice([1, 2])) + "".join(str(rng.randint(0, 9)) for _ in range(8))
    return first9 + str(npi_check_digit(first9))


def make_ssn(rng: random.Random) -> str:
    # 900-999 area numbers are never issued as SSNs -> clearly synthetic.
    return f"{rng.randint(900, 999)}-{rng.randint(1, 99):02d}-{rng.randint(1, 9999):04d}"


def make_patient(i: int, rng: random.Random, providers: list[str]) -> dict:
    first, last = rng.choice(FIRST_NAMES), rng.choice(LAST_NAMES)
    dob = date(1940, 1, 1) + timedelta(days=rng.randint(0, 365 * 70))
    city, state, zip3 = rng.choice(CITIES)
    prefix, plan_name = rng.choice(PLANS)
    pcp = rng.choice(providers)
    claims = []
    for c in range(rng.randint(1, 4)):
        code, desc = rng.choice(CPT)
        claims.append({
            "claim_id": f"CLM-{i:04d}-{c + 1}",
            "service_date": (date(2025, 1, 1) + timedelta(days=rng.randint(0, 600))).isoformat(),
            "cpt": code,
            "description": desc,
            "icd10": rng.choice(ICD10),
            "billed_amount": round(rng.uniform(80, 1800), 2),
            "rendering_npi": rng.choice(providers),
        })
    return {
        "id": i,
        "mrn": f"MRN-{rng.randint(1_000_000, 9_999_999)}",
        "first_name": first,
        "last_name": last,
        "dob": dob.isoformat(),
        "sex": rng.choice(["F", "M"]),
        "address": {
            "line": f"{rng.randint(10, 9999)} {rng.choice(STREETS)} {rng.choice(STREET_TYPES)}",
            "city": city,
            "state": state,
            "zip": f"{zip3}{rng.randint(0, 99):02d}",
        },
        "phone": f"({rng.choice(AREA_CODES)}) 555-01{rng.randint(0, 99):02d}",
        "email": f"{first.lower()}.{last.lower()}{rng.randint(1, 99)}@{rng.choice(['example.com', 'example.org'])}",
        "ssn": make_ssn(rng),
        "member_id": f"{prefix}{rng.randint(100_000_000, 999_999_999)}",
        "plan": plan_name,
        "pcp_npi": pcp,
        "claims": claims,
        "synthetic": True,
    }


def generate(count: int, seed: int) -> list[dict]:
    rng = random.Random(seed)
    providers = [make_npi(rng) for _ in range(25)]
    return [make_patient(i, rng, providers) for i in range(1, count + 1)]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--count", type=int, default=200)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default="app/sample-ehr/data/patients.json")
    args = ap.parse_args()
    patients = generate(args.count, args.seed)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(patients, indent=2))
    print(f"wrote {len(patients)} synthetic patients -> {out}")


if __name__ == "__main__":
    main()
