#!/usr/bin/env python3
"""Inject exactly 50 labelled PHI leaks (plus unlabelled-PHI decoys) and record ground truth.

Composition (fixed, asserted):
  40 log leaks       printed to stdout by a Job in the `phi` namespace -> Fluent Bit -> Presidio
  10 runtime events  6 egress connects to TEST-NET-3 (203.0.113.0/24, never routed),
                     2 shell spawns, 2 reads of a mounted secret            -> Falco
  30 decoys          PHI-free lines that look tricky (order ids, epoch timestamps,
                     build dates, capitalised phrases) used to measure false positives

Every seeded line ends with a marker `rid=seed-<ID>` (L = leak, D = decoy) and every
runtime event carries `SEED-R<NN>` in its process arguments. The detectors never
see the ground-truth file; measure.py joins on these markers afterwards.

Modes:
  --local FILE   write the 70 log lines to FILE for offline scanning (no cluster)
  --apply        create the ConfigMap/Secret/Job in the cluster and run it
  (default)      just write the plan, ground truth and Job manifest under build/seed/
"""
from __future__ import annotations

import argparse
import json
import random
import shutil
import subprocess
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
N_LOG_LEAKS, N_EGRESS, N_SHELL, N_SECRET, N_DECOYS = 40, 6, 2, 2, 30
TOTAL_LEAKS = N_LOG_LEAKS + N_EGRESS + N_SHELL + N_SECRET
assert TOTAL_LEAKS == 50, "the seeded leak count must be exactly 50"

RULE_EGRESS = "PHI Guard - Unexpected egress from PHI pod"
RULE_SHELL = "PHI Guard - Shell spawned in PHI pod"
RULE_SECRET = "PHI Guard - Mounted secret read in PHI pod"


def _name(p: dict) -> str:
    return f"{p['first_name']} {p['last_name']}"


def _us(d: str) -> str:
    return date.fromisoformat(d).strftime("%m/%d/%Y")


def _long(d: str) -> str:
    return date.fromisoformat(d).strftime("%b %d, %Y")


# Each template -> (text, expected entity types). Context-free variants are included on
# purpose; they are expected to be harder and the measured recall should show it.
LEAK_TEMPLATES = [
    lambda p: (f"patient lookup ok name={_name(p)}", ["PERSON"]),
    lambda p: (json.dumps({"event": "claim_submitted", "ssn": p["ssn"]}), ["US_SSN"]),
    lambda p: (f"DOB: {_us(p['dob'])} confirmed for {p['mrn']}", ["DATE_TIME", "MEDICAL_RECORD_NUMBER"]),
    lambda p: (f"eligibility check member_id={p['member_id']} status=active", ["HEALTH_PLAN_ID"]),
    lambda p: (f"rendering provider NPI {p['pcp_npi']} attached to claim", ["US_NPI"]),
    lambda p: (f"callback requested phone={p['phone']}", ["PHONE_NUMBER"]),
    lambda p: (f"statement emailed to {p['email']}", ["EMAIL_ADDRESS"]),
    lambda p: (f"GET /patients/search?name={p['first_name']}+{p['last_name']}&dob={p['dob']} 200",
               ["PERSON", "DATE_TIME"]),
    lambda p: (f"ERROR KeyError('plan') record={{'mrn': '{p['mrn']}', 'name': '{_name(p)}'}}",
               ["MEDICAL_RECORD_NUMBER", "PERSON"]),
    lambda p: (f"identity verified ssn={p['ssn'].replace('-', '')}", ["US_SSN"]),
    lambda p: (f"subscriber {p['member_id']} born {_long(p['dob'])}", ["HEALTH_PLAN_ID", "DATE_TIME"]),
    lambda p: (f"Patient {_name(p)} (MRN {p['mrn'][4:]}) admitted to ward 4B", ["PERSON", "MEDICAL_RECORD_NUMBER"]),
    # context-free variants (harder)
    lambda p: (f"cache key {p['member_id']} warmed", ["HEALTH_PLAN_ID"]),
    lambda p: (f"forwarding to {p['pcp_npi']} queue", ["US_NPI"]),
]

TEMPLATE_NAMES = [
    "name as key=value",
    "SSN inside JSON",
    "DOB + MRN",
    "member_id as key=value",
    "provider NPI with context",
    "phone as key=value",
    "email address",
    "name + DOB in URL query",
    "MRN + name in exception dump",
    "compact SSN (no dashes)",
    "member ID + long-form DOB",
    "patient name + bare MRN",
    "member ID, no context words (hard)",
    "NPI, no context words (hard)",
]
assert len(TEMPLATE_NAMES) == len(LEAK_TEMPLATES)

DECOY_LINES = [
    "GET /healthz 200 0.8ms",
    "GET /readyz 200 1.1ms",
    "order ORD123456789 shipped to warehouse 7",
    "invoice INV987654321 settled",
    "batch BAT555444333 queued for retry",
    "processed 1234567 records in 4.2s",
    "cache hit ratio 0.93 over 7654321 lookups",
    "epoch 1731400000 checkpoint written",
    "epoch 2731400017 compaction finished",
    "build 2026-11-01 deployed to staging",
    "certificate renews on 2027-01-15",
    "Health Check Passed for Upstream Pool",
    "Scheduled Maintenance Window Starts Soon",
    "connection from 10.244.1.17:53122 accepted",
    "request_id=7f3c9a1e2b4d4f60 latency_ms=42",
    "trace 4bf92f3577b34da6a3ce929d0e0e4736 sampled",
    "uuid 3fa85f64-5717-4562-b3fc-2c963f66afa6 created",
    "price updated to 1299.99 USD",
    "version 3.11.9 build 20261101",
    "retrying in 5000 ms (attempt 3 of 5)",
    "user admin logged in from console",
    "Worker Pool Alpha scaled to 4 replicas",
    "queue depth 128 threshold 512",
    "feature flag new_claims_ui enabled for 25%",
    "port 5432 reachable on db.internal",
    "sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 verified",
    "disk usage 71% on /var/lib/data",
    "Grace Period Ends For Batch Jobs",
    "release train 2026.11 merged",
    "rate limit 100 req/min applied to tenant acme",
]


def build_plan(patients: list[dict], seed: int) -> tuple[dict, dict]:
    rng = random.Random(seed)
    log_lines, leaks, decoys, runtime = [], [], [], []

    picks = rng.sample(patients, N_LOG_LEAKS)
    for i, p in enumerate(picks, start=1):
        sid = f"L{i:03d}"
        text, expected = LEAK_TEMPLATES[(i - 1) % len(LEAK_TEMPLATES)](p)
        log_lines.append({"id": sid, "text": f"{text} rid=seed-{sid}"})
        t = (i - 1) % len(LEAK_TEMPLATES)
        leaks.append({"id": sid, "kind": "log", "expected_entities": expected, "template": t,
                      "template_name": TEMPLATE_NAMES[t], "marker": f"rid=seed-{sid}"})

    assert len(DECOY_LINES) == N_DECOYS
    for i, text in enumerate(DECOY_LINES, start=1):
        sid = f"D{i:03d}"
        log_lines.append({"id": sid, "text": f"{text} rid=seed-{sid}"})
        decoys.append({"id": sid, "kind": "decoy", "marker": f"rid=seed-{sid}"})
    rng.shuffle(log_lines)

    n = 0
    for i in range(N_EGRESS):
        n += 1
        sid = f"R{n:03d}"
        runtime.append({"id": sid, "kind": "egress", "ip": f"203.0.113.{10 + i}", "port": 4441 + i,
                        "marker": f"SEED-{sid}", "expected_rule": RULE_EGRESS})
    for _ in range(N_SHELL):
        n += 1
        sid = f"R{n:03d}"
        runtime.append({"id": sid, "kind": "shell", "marker": f"SEED-{sid}", "expected_rule": RULE_SHELL})
    for _ in range(N_SECRET):
        n += 1
        sid = f"R{n:03d}"
        runtime.append({"id": sid, "kind": "secret_read", "path": "/etc/phi-secrets/db-password",
                        "marker": f"SEED-{sid}", "expected_rule": RULE_SECRET})

    plan = {"log_lines": log_lines, "runtime": runtime}
    truth = {"seed": seed, "total_leaks": len(leaks) + len(runtime), "log_leaks": leaks,
             "runtime_leaks": runtime, "decoys": decoys}
    assert truth["total_leaks"] == TOTAL_LEAKS
    return plan, truth


def job_manifest(image: str) -> str:
    return f"""apiVersion: batch/v1
kind: Job
metadata:
  name: phi-leak-seeder
  namespace: phi
  labels:
    app.kubernetes.io/name: phi-leak-seeder
    data-classification: phi
    audit.phi-guard.io/log: enabled
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: 3600
  template:
    metadata:
      labels:
        app.kubernetes.io/name: phi-leak-seeder
        data-classification: phi
        audit.phi-guard.io/log: enabled
    spec:
      restartPolicy: Never
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: seeder
          image: {image}
          imagePullPolicy: IfNotPresent
          command: ["python", "/seed/run_seed.py", "/seed/plan.json"]
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          resources:
            requests: {{cpu: 50m, memory: 64Mi}}
            limits: {{cpu: 250m, memory: 128Mi}}
          volumeMounts:
            - {{name: seed, mountPath: /seed, readOnly: true}}
            - {{name: phi-secrets, mountPath: /etc/phi-secrets, readOnly: true}}
      volumes:
        - name: seed
          configMap:
            name: phi-leak-seeder
        - name: phi-secrets
          secret:
            secretName: phi-db-credentials
"""


def kubectl(*args: str, stdin: str | None = None) -> None:
    subprocess.run(["kubectl", *args], input=stdin, text=True, check=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--patients", default="app/sample-ehr/data/patients.json")
    ap.add_argument("--seed", type=int, default=2026)
    ap.add_argument("--out", default="build/seed")
    ap.add_argument("--truth", default="evidence/ground_truth.json")
    ap.add_argument("--image", default="phi-guard/sample-ehr:0.1.0")
    ap.add_argument("--local", metavar="FILE", help="write log lines to FILE instead of running in-cluster")
    ap.add_argument("--apply", action="store_true", help="run the seeder Job in the cluster")
    args = ap.parse_args()

    patients_path = ROOT / args.patients
    if not patients_path.exists():
        sys.exit(f"{args.patients} not found; run `make data` first")
    patients = json.loads(patients_path.read_text())

    plan, truth = build_plan(patients, args.seed)
    out = ROOT / args.out
    out.mkdir(parents=True, exist_ok=True)
    (out / "plan.json").write_text(json.dumps(plan, indent=2))
    shutil.copy(ROOT / "scripts" / "run_seed.py", out / "run_seed.py")
    (out / "seeder-job.yaml").write_text(job_manifest(args.image))
    truth_path = ROOT / args.truth
    truth_path.parent.mkdir(parents=True, exist_ok=True)
    truth_path.write_text(json.dumps(truth, indent=2))
    print(f"ground truth: {truth['total_leaks']} leaks ({N_LOG_LEAKS} log, {len(truth['runtime_leaks'])} runtime) "
          f"+ {N_DECOYS} decoys -> {args.truth}")

    if args.local:
        p = ROOT / args.local
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("\n".join(line["text"] for line in plan["log_lines"]) + "\n")
        print(f"wrote {len(plan['log_lines'])} log lines -> {args.local} (runtime events need a cluster)")

    if args.apply:
        kubectl("-n", "phi", "delete", "job", "phi-leak-seeder", "--ignore-not-found", "--wait=true")
        cm = subprocess.run(["kubectl", "-n", "phi", "create", "configmap", "phi-leak-seeder",
                             f"--from-file=plan.json={out / 'plan.json'}",
                             f"--from-file=run_seed.py={out / 'run_seed.py'}",
                             "--dry-run=client", "-o", "yaml"], capture_output=True, text=True, check=True).stdout
        kubectl("apply", "-f", "-", stdin=cm)
        secret = subprocess.run(["kubectl", "-n", "phi", "create", "secret", "generic", "phi-db-credentials",
                                 "--from-literal=db-password=synthetic-demo-only-not-a-secret",
                                 "--dry-run=client", "-o", "yaml"], capture_output=True, text=True, check=True).stdout
        kubectl("apply", "-f", "-", stdin=secret)
        kubectl("apply", "-f", str(out / "seeder-job.yaml"))
        kubectl("-n", "phi", "wait", "--for=condition=complete", "job/phi-leak-seeder", "--timeout=180s")
        print("seeder job complete; give Fluent Bit a few seconds before `make measure`")
    return 0


if __name__ == "__main__":
    sys.exit(main())
