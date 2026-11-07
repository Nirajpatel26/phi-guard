#!/usr/bin/env python3
"""Python-only PHI Guard demo: no Docker, no cluster, about 10 seconds.

Runs the project's real code on synthetic data:
  1. generate 200 synthetic patients
  2. run the services' logging code with LEAK_MODE=off and LEAK_MODE=on and scan every line
  3. build the 50-leak ground truth and score the 40 log leaks + 30 decoys
     (the 10 runtime events need Falco in a cluster, so they are reported as not evaluated)
  4. count implemented HIPAA controls from mapping.yaml + the policy files
  5. demonstrate the CI gate and the triage assistant on the sample findings in tests/fixtures
     (the real Terraform/Conftest/Checkov scan runs with `make report` / `make demo`)

Writes evidence/demo/demo-offline.{json,html}. Uses Presidio when installed, otherwise the
regex-only lite engine; the engine name is printed and stored with every number.

    python scripts/demo_offline.py            # or: make demo-offline
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import logging
import os
import platform
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for _p in (ROOT, ROOT / "app" / "sample-ehr"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import yaml  # noqa: E402

from detector.presidio.engine import build_engine, scan_line  # noqa: E402
from ehr import phi_logging  # noqa: E402
from scripts import report as report_mod  # noqa: E402
from scripts.generate_patients import generate  # noqa: E402
from scripts.measure import measure_controls, score_detection  # noqa: E402
from scripts.seed_leaks import build_plan  # noqa: E402
from triage.explain import explain_one  # noqa: E402
from triage.providers import get_provider  # noqa: E402

SERVICES = [("patient-api", "patient_read"), ("claims-api", "claim_submitted"),
            ("eligibility-api", "eligibility_check")]
FIXTURES = ROOT / "tests" / "fixtures"
SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


@contextlib.contextmanager
def leak_mode(value: str):
    old = os.environ.get("LEAK_MODE")
    os.environ["LEAK_MODE"] = value
    try:
        yield
    finally:
        if old is None:
            os.environ.pop("LEAK_MODE", None)
        else:
            os.environ["LEAK_MODE"] = old


def app_logging(engine, patients: list[dict], mode: str, n: int) -> list[dict]:
    """Call the exact logging code the three services use, then scan each line."""
    logger = logging.getLogger(f"phi-guard-demo-{mode}")
    logger.handlers[:] = [logging.NullHandler()]
    logger.propagate = False
    rng = random.Random(7)
    rows = []
    with leak_mode(mode):
        for i in range(n):
            service, event = SERVICES[i % len(SERVICES)]
            line = phi_logging.log_patient_event(logger, event, rng.choice(patients), f"req{i:04d}")
            r = scan_line(engine, line)
            rows.append({"service": service, "line": line, "masked": r.masked, "severity": r.severity,
                         "entities": sorted({f.entity for f in r.findings})})
    return rows


def seeded_detection(engine, patients: list[dict]) -> dict:
    plan, truth = build_plan(patients, 2026)
    text = {line["id"]: line["text"] for line in plan["log_lines"]}
    scans = {line["id"]: scan_line(engine, line["text"]) for line in plan["log_lines"]}
    alerts = [{"source": {"pod": "phi-leak-seeder-offline"}, "engine": r.engine, "masked_line": r.masked,
               "entities": [{"type": f.entity, "score": f.score} for f in r.findings]}
              for r in scans.values() if r.findings]
    masked = [{"masked": r.masked} for r in scans.values()]
    det = score_detection(truth, alerts, masked, None)

    examples, seen = [], set()
    for leak in truth["log_leaks"]:
        if leak["template"] in seen:
            continue
        seen.add(leak["template"])
        r = scans[leak["id"]]
        examples.append({"id": leak["id"], "template": leak["template_name"], "line": text[leak["id"]],
                         "masked": r.masked, "expected": leak["expected_entities"],
                         "found": sorted({f.entity for f in r.findings}), "detected": bool(r.findings)})
    decoys = [{"id": d["id"], "line": text[d["id"]], "flagged": bool(scans[d["id"]].findings),
               "found": sorted({f.entity for f in scans[d["id"]].findings})} for d in truth["decoys"]]
    return {"score": det, "examples": examples, "decoys": decoys,
            "runtime_events": [{"id": r["id"], "kind": r["kind"], "rule": r["expected_rule"]}
                               for r in truth["runtime_leaks"]]}


def gate_and_triage(out_dir: Path, n_triage: int) -> dict:
    base = ["--plan", str(FIXTURES / "tfplan_min.json"),
            "--conftest-tf", str(FIXTURES / "conftest_tf.json"),
            "--conftest-k8s", str(FIXTURES / "conftest_k8s.json"),
            "--checkov", str(FIXTURES / "checkov.json"),
            "--out-dir", str(out_dir),
            "--banner", "SAMPLE: rendered from tests/fixtures (hand-written tool output), not a scan of this repo"]
    with contextlib.redirect_stdout(io.StringIO()):
        rc_strict = report_mod.main(base + ["--no-waivers", "--fail-on", "HIGH"])
        strict = json.loads((out_dir / "compliance-report.json").read_text())["summary"]
        rc_waived = report_mod.main(base + ["--fail-on", "HIGH"])   # last run = the files left on disk
    rep = json.loads((out_dir / "compliance-report.json").read_text())

    mapping = yaml.safe_load((ROOT / "policies" / "mapping.yaml").read_text())
    controls = {c["id"]: {**c, "safeguard": mapping["citations"][c["citation"]]} for c in mapping["controls"]}
    findings = sorted((r for r in rep["results"] if r["status"] in ("FAIL", "WAIVED")),
                      key=lambda r: (SEVERITY_ORDER[r["severity"]], r["control_id"], r["resource"]))
    picks, kinds = [], set()
    for f in findings:   # one example per (engine, terraform/kubernetes) pair for variety
        kind = (f["engine"], "kubernetes" if "/" in f["resource"] else "terraform")
        if kind not in kinds:
            kinds.add(kind)
            picks.append(f)
        if len(picks) == n_triage:
            break
    provider, note = get_provider()
    triage = []
    for f in picks:
        t = explain_one(provider, f, controls[f["control_id"]], controls)
        triage.append({"finding": {k: f[k] for k in ("control_id", "resource", "file", "line", "engine", "check_id",
                                                     "severity", "status")}, "triage": t})
    return {
        "gate": {"strict": {"exit_code": rc_strict, "high": strict["unwaived_fail_by_severity"]["HIGH"],
                            "fail": strict["fail"]},
                 "with_waivers": {"exit_code": rc_waived, "high": rep["summary"]["unwaived_fail_by_severity"]["HIGH"],
                                  "waived": rep["summary"]["waived"]}},
        "sample_report": report_mod.rel(out_dir / "compliance-report.html"),
        "triage_provider": provider.name, "triage_note": note, "triage": triage,
    }


def render_html(data: dict, path: Path) -> None:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    env = Environment(loader=FileSystemLoader(ROOT / "scripts" / "templates"),
                      autoescape=select_autoescape(["html", "j2"]), trim_blocks=True, lstrip_blocks=True)
    path.write_text(env.get_template("demo-offline.html.j2").render(d=data))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out-dir", default="evidence/demo")
    ap.add_argument("--engine", choices=["auto", "presidio", "lite"], default="auto")
    ap.add_argument("--requests", type=int, default=30, help="simulated service calls per LEAK_MODE")
    ap.add_argument("--triage", type=int, default=3, help="number of triage examples")
    args = ap.parse_args(argv)

    t0 = time.monotonic()
    out_dir = ROOT / args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    print("PHI Guard offline demo (Python only; Kubernetes parts need `make demo`)")
    print("\n[1/5] Generating 200 synthetic patients")
    patients = generate(200, 42)
    engine = build_engine(args.engine)
    print(f"      done. Detection engine: {engine.name}")

    print(f"[2/5] Running the services' logging code, {args.requests} calls with LEAK_MODE=off and =on")
    logs_off = app_logging(engine, patients, "off", args.requests)
    logs_on = app_logging(engine, patients, "on", args.requests)
    off_alerts = sum(1 for r in logs_off if r["entities"])
    on_alerts = sum(1 for r in logs_on if r["entities"])
    print(f"      LEAK_MODE=off: {off_alerts}/{len(logs_off)} lines flagged | "
          f"LEAK_MODE=on: {on_alerts}/{len(logs_on)} lines flagged")

    print("[3/5] Seeding 50 labelled leaks + 30 decoys and scoring the 40 log leaks")
    seeded = seeded_detection(engine, patients)
    s = seeded["score"]
    print(f"      caught {s['log']['caught']}/{s['log']['total']} log leaks, "
          f"{s['false_positives']['decoys_flagged']}/{s['false_positives']['decoys_total']} decoys flagged, "
          f"precision {s['precision']}, recall {s['recall']} (10 Falco runtime events: not evaluated here)")

    print("[4/5] Counting HIPAA controls")
    controls = measure_controls()
    print(f"      {controls['implemented']}/{controls['defined']} controls implemented "
          f"({controls['by_engine']['rego']} Rego, {controls['by_engine']['checkov']} Checkov)")

    print("[5/5] CI gate + triage on the sample findings (tests/fixtures)")
    gt = gate_and_triage(out_dir, args.triage)
    g = gt["gate"]
    print(f"      gate strict: exit {g['strict']['exit_code']} ({g['strict']['high']} unwaived HIGH) | "
          f"with waivers: exit {g['with_waivers']['exit_code']} ({g['with_waivers']['waived']} waived)")
    print(f"      triage provider: {gt['triage_provider']}"
          + (f" ({gt['triage_note']})" if gt["triage_note"] else ""))
    for item in gt["triage"]:
        f, t = item["finding"], item["triage"]
        print(f"        {f['control_id']:<11} {t['hipaa_citation']:<26} {f['resource']}")

    data = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "python": platform.python_version(),
        "engine": engine.name,
        "seconds": round(time.monotonic() - t0, 2),
        "patients": len(patients),
        "app_logging": {"off": logs_off, "on": logs_on, "off_alerts": off_alerts, "on_alerts": on_alerts},
        "seeded": seeded,
        "controls": controls,
        **gt,
    }
    (out_dir / "demo-offline.json").write_text(json.dumps(data, indent=2))
    render_html(data, out_dir / "demo-offline.html")
    print(f"\nDone in {data['seconds']}s. Open {args.out_dir}/demo-offline.html")
    return 0


if __name__ == "__main__":
    sys.exit(main())
