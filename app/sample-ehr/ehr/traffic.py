"""Generate steady traffic across all three services.

Run locally against the ingress:   python -m ehr.traffic --base https://localhost --insecure
Run in-cluster as a Job:            python -m ehr.traffic --in-cluster
"""
from __future__ import annotations

import argparse
import json
import random
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path


def call(url: str, ctx: ssl.SSLContext | None, data: dict | None = None) -> int:
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers={"content-type": "application/json"},
                                 method="POST" if data is not None else "GET")
    try:
        with urllib.request.urlopen(req, timeout=5, context=ctx) as r:  # noqa: S310
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:  # noqa: BLE001 - traffic generator should keep going
        return 0


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="https://localhost")
    ap.add_argument("--in-cluster", action="store_true")
    ap.add_argument("--insecure", action="store_true", help="accept the self-signed demo cert")
    ap.add_argument("--requests", type=int, default=60)
    ap.add_argument("--data", default=str(Path(__file__).resolve().parent.parent / "data" / "patients.json"))
    args = ap.parse_args()

    patients = json.loads(Path(args.data).read_text())
    ctx = ssl._create_unverified_context() if args.insecure else None  # noqa: S323 - demo self-signed cert
    if args.in_cluster:
        urls = {"patients": "http://patient-api:8000", "claims": "http://claims-api:8000",
                "eligibility": "http://eligibility-api:8000"}
    else:
        urls = {k: args.base.rstrip("/") for k in ("patients", "claims", "eligibility")}

    rng = random.Random(7)
    codes: dict[int, int] = {}
    for _ in range(args.requests):
        p = rng.choice(patients)
        kind = rng.choice(["patient", "search", "claim", "claim_read", "eligibility"])
        if kind == "patient":
            s = call(f"{urls['patients']}/patients/{p['id']}", ctx)
        elif kind == "search":
            s = call(f"{urls['patients']}/patients?name={p['last_name']}", ctx)
        elif kind == "claim":
            s = call(f"{urls['claims']}/claims", ctx,
                     {"patient_id": p["id"], "cpt": "99213", "icd10": "I10", "billed_amount": 120.0})
        elif kind == "claim_read":
            s = call(f"{urls['claims']}/claims/{p['claims'][0]['claim_id']}", ctx)
        else:
            s = call(f"{urls['eligibility']}/eligibility/{p['member_id']}", ctx)
        codes[s] = codes.get(s, 0) + 1
        time.sleep(0.05)
    print(f"traffic done: {args.requests} requests, status codes {codes}")


if __name__ == "__main__":
    main()
