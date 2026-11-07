#!/usr/bin/env python3
"""Compute PHI Guard's results from real artifacts. Nothing here is hard-coded.

Subcommands
  controls   count controls defined / implemented / evaluated (mapping + policy files + last report)
  ci         CI pipeline duration (from `gh run list` or evidence/ci_timing*.json files)
  detect     leak-detection recall/precision against evidence/ground_truth.json
  review     manual vs LLM-assisted review time (evidence/review_times.json, from review_eval.py)
  all        everything above; writes evidence/results.json and evidence/results.md

detect sources
  --cluster          read alerts via `kubectl exec` into the scanner and Falco logs via `kubectl logs`
  --offline          scan evidence/seed_lines.log locally (log leaks only; runtime events not evaluated)
  --alerts/--falco   use saved files
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import statistics
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import yaml  # noqa: E402

EVIDENCE = ROOT / "evidence"
LOG_MARKER = re.compile(r"rid=seed-([LD]\d{3})")
RUNTIME_MARKER = re.compile(r"SEED-(R\d{3})")


# ----------------------------------------------------------------------------- controls
def measure_controls() -> dict:
    mapping = yaml.safe_load((ROOT / "policies" / "mapping.yaml").read_text())
    rego_text = "\n".join(p.read_text() for p in (ROOT / "policies" / "rego").rglob("*.rego")
                          if not p.name.endswith("_test.rego"))
    custom_checkov = "\n".join(p.read_text() for p in (ROOT / "policies" / "checkov").glob("*.py"))
    implemented, missing = [], []
    for c in mapping["controls"]:
        if c["engine"] == "rego":
            ok = f'"{c["id"]}"' in rego_text
        else:
            ok = all((cid in custom_checkov) if cid.startswith("CKV_PHI") else bool(re.match(r"^CKV2?_[A-Z0-9]+_\d+$", cid))
                     for cid in c["checks"])
        (implemented if ok else missing).append(c["id"])

    evaluated = None
    report_path = EVIDENCE / "compliance-report.json"
    if report_path.exists():
        rep = json.loads(report_path.read_text())
        evaluated = rep["summary"]["controls_evaluated"]
    by_citation: dict[str, int] = {}
    for c in mapping["controls"]:
        by_citation[c["citation"]] = by_citation.get(c["citation"], 0) + 1
    return {"defined": len(mapping["controls"]), "implemented": len(implemented), "missing": missing,
            "evaluated_in_last_report": evaluated, "by_citation": by_citation,
            "by_engine": {e: sum(1 for c in mapping["controls"] if c["engine"] == e) for e in ("rego", "checkov")}}


# ----------------------------------------------------------------------------- ci
def measure_ci(limit: int = 10) -> dict:
    files = sorted(EVIDENCE.glob("ci_timing*.json"))
    durations = []
    source = None
    for f in files:
        try:
            durations.append(float(json.loads(f.read_text())["seconds"]))
            source = "evidence/ci_timing*.json"
        except (ValueError, KeyError):
            continue
    if not durations and shutil.which("gh"):
        proc = subprocess.run(["gh", "run", "list", "--workflow", "compliance.yml", "--status", "completed",
                               "-L", str(limit), "--json", "createdAt,updatedAt,conclusion,databaseId"],
                              cwd=ROOT, capture_output=True, text=True)
        if proc.returncode == 0 and proc.stdout.strip():
            for run in json.loads(proc.stdout):
                start = datetime.fromisoformat(run["createdAt"].replace("Z", "+00:00"))
                end = datetime.fromisoformat(run["updatedAt"].replace("Z", "+00:00"))
                durations.append((end - start).total_seconds())
            source = "gh run list (wall clock incl. queueing)"
    if not durations:
        return {"available": False, "note": "no CI timing yet: push to GitHub, then download the evidence "
                                            "artifact's ci_timing.json into evidence/ or install gh CLI"}
    return {"available": True, "source": source, "runs": len(durations),
            "mean_seconds": round(statistics.mean(durations), 1),
            "median_seconds": round(statistics.median(durations), 1),
            "max_seconds": round(max(durations), 1), "target_seconds": 180,
            "meets_target": max(durations) < 180}


# ----------------------------------------------------------------------------- detect
def _jsonl(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def _kubectl(*args: str) -> str:
    proc = subprocess.run(["kubectl", *args], capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"kubectl {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


def _falco_ready() -> bool:
    proc = subprocess.run(["kubectl", "-n", "falco", "get", "pods", "-l", "app.kubernetes.io/name=falco",
                           "-o", "json"], capture_output=True, text=True)
    if proc.returncode != 0:
        return False
    for pod in json.loads(proc.stdout or "{}").get("items", []):
        for cs in (pod.get("status") or {}).get("containerStatuses") or []:
            if cs.get("name") == "falco" and cs.get("ready"):
                return True
    return False


def collect_cluster() -> tuple[list[dict], list[dict], list[dict] | None]:
    alerts = _jsonl(_kubectl("-n", "logging", "exec", "deploy/phi-scanner", "--", "sh", "-c",
                             "cat /data/alerts.jsonl 2>/dev/null || true"))
    masked = _jsonl(_kubectl("-n", "logging", "exec", "deploy/phi-scanner", "--", "sh", "-c",
                             "cat /data/masked.jsonl 2>/dev/null || true"))
    falco: list[dict] | None = None   # None = runtime detection not evaluated (never counted as misses)
    if _falco_ready():
        proc = subprocess.run(["kubectl", "-n", "falco", "logs", "-l", "app.kubernetes.io/name=falco",
                               "-c", "falco", "--tail=-1", "--max-log-requests=10"], capture_output=True, text=True)
        if proc.returncode == 0:
            falco = _jsonl(proc.stdout)
    if falco is None:
        print("note: Falco is not running/ready, so the 10 runtime events are reported as 'not evaluated'",
              file=sys.stderr)
    return alerts, masked, falco


def score_detection(truth: dict, alerts: list[dict], masked: list[dict] | None,
                    falco: list[dict] | None) -> dict:
    alerts = [a for a in alerts if (a.get("source") or {}).get("pod", "").startswith("phi-leak-seeder")]
    alerted: dict[str, dict] = {}
    for a in alerts:
        m = LOG_MARKER.search(a.get("masked_line", ""))
        if m:
            alerted[m.group(1)] = a
    delivered = None
    if masked is not None:
        delivered = {m.group(1) for r in masked if (m := LOG_MARKER.search(r.get("masked", "")))}

    log_rows = []
    for leak in truth["log_leaks"]:
        a = alerted.get(leak["id"])
        got = sorted({e["type"] for e in a["entities"]}) if a else []
        log_rows.append({"id": leak["id"], "detected": a is not None, "expected": leak["expected_entities"],
                         "found": got, "all_expected_found": set(leak["expected_entities"]) <= set(got),
                         "template": leak["template"], "template_name": leak.get("template_name"),
                         "delivered": None if delivered is None else leak["id"] in delivered})
    decoy_fp = [d["id"] for d in truth["decoys"] if d["id"] in alerted]
    decoy_fp_entities = {d: sorted({e["type"] for e in alerted[d]["entities"]}) for d in decoy_fp}

    runtime_rows, runtime_fp = [], []
    runtime_evaluated = falco is not None
    if runtime_evaluated:
        events = [e for e in falco if "phi_guard" in (e.get("tags") or []) or
                  str(e.get("rule", "")).startswith("PHI Guard")]
        hits: dict[str, set[str]] = {}
        for e in events:
            cmd = str((e.get("output_fields") or {}).get("proc.cmdline", "")) + " " + str(e.get("output", ""))
            m = RUNTIME_MARKER.search(cmd)
            pod = str((e.get("output_fields") or {}).get("k8s.pod.name", ""))
            if m:
                hits.setdefault(m.group(1), set()).add(e.get("rule", ""))
            elif pod.startswith("phi-leak-seeder"):
                runtime_fp.append(e.get("rule", ""))
        for ev in truth["runtime_leaks"]:
            rules = hits.get(ev["id"], set())
            runtime_rows.append({"id": ev["id"], "kind": ev["kind"], "detected": bool(rules),
                                 "correct_rule": ev["expected_rule"] in rules, "rules": sorted(rules)})

    log_tp = sum(r["detected"] for r in log_rows)
    rt_tp = sum(r["detected"] for r in runtime_rows)
    tp = log_tp + rt_tp
    fp = len(decoy_fp) + len(runtime_fp)
    denominator = len(truth["log_leaks"]) + (len(truth["runtime_leaks"]) if runtime_evaluated else 0)
    per_entity: dict[str, dict] = {}
    for r in log_rows:
        for ent in r["expected"]:
            s = per_entity.setdefault(ent, {"expected": 0, "found": 0})
            s["expected"] += 1
            s["found"] += ent in r["found"]
    engines = sorted({a.get("engine", "?") for a in alerts})
    return {
        "engine": engines,
        "total_seeded_leaks": truth["total_leaks"],
        "evaluated_leaks": denominator,
        "runtime_evaluated": runtime_evaluated,
        "caught": tp,
        "log": {"caught": log_tp, "total": len(truth["log_leaks"]),
                "all_expected_entities_found": sum(r["all_expected_found"] for r in log_rows),
                "delivered": None if delivered is None else sum(bool(r["delivered"]) for r in log_rows)},
        "runtime": {"caught": rt_tp, "total": len(truth["runtime_leaks"]),
                    "correct_rule": sum(r["correct_rule"] for r in runtime_rows)} if runtime_evaluated else None,
        "false_positives": {"decoys_flagged": len(decoy_fp), "decoys_total": len(truth["decoys"]),
                            "decoy_ids": decoy_fp, "decoy_entities": decoy_fp_entities,
                            "runtime_unmatched": len(runtime_fp)},
        "precision": round(tp / (tp + fp), 3) if tp + fp else None,
        "recall": round(tp / denominator, 3) if denominator else None,
        "per_entity_recall": {k: round(v["found"] / v["expected"], 3) for k, v in sorted(per_entity.items())},
        "missed": [r["id"] for r in log_rows + runtime_rows if not r["detected"]],
        "rows": {"log": log_rows, "runtime": runtime_rows},
    }


def measure_detect(args: argparse.Namespace) -> dict:
    truth_path = EVIDENCE / "ground_truth.json"
    if not truth_path.exists():
        return {"available": False, "note": "run `make seed` (or `make seed-offline`) first"}
    truth = json.loads(truth_path.read_text())
    if getattr(args, "cluster", False):
        alerts, masked, falco = collect_cluster()
        mode = "cluster"
    elif getattr(args, "offline", False):
        from detector.presidio.scan_file import scan_file
        lines = EVIDENCE / "seed_lines.log"
        if not lines.exists():
            return {"available": False, "note": "run `make seed-offline` first"}
        info = scan_file(lines, EVIDENCE / "offline", args.engine)
        alerts = _jsonl((EVIDENCE / "offline" / "alerts.jsonl").read_text())
        masked = _jsonl((EVIDENCE / "offline" / "masked.jsonl").read_text())
        falco = None
        mode = f"offline ({info['engine']})"
    elif not args.alerts:
        saved = EVIDENCE / "detection-results.json"
        if saved.exists():
            return json.loads(saved.read_text())
        return {"available": False, "note": "run `make measure-detect` (cluster) or `make seed-offline measure-offline`"}
    else:
        alerts = _jsonl(Path(args.alerts).read_text())
        masked = None
        falco = _jsonl(Path(args.falco).read_text()) if args.falco else None
        mode = "files"
    result = score_detection(truth, alerts, masked, falco)
    result["mode"] = mode
    result["available"] = True
    return result


# ----------------------------------------------------------------------------- review
def measure_review() -> dict:
    path = EVIDENCE / "review_times.json"
    if not path.exists():
        return {"available": False, "note": "run `make review-eval` (interactive, ~10 minutes)"}
    data = json.loads(path.read_text())
    out = {"available": True, "reviewer": data.get("reviewer"), "items": len(data["items"])}
    for cond in ("manual", "assisted"):
        times = [i["seconds"] for i in data["items"] if i["condition"] == cond]
        correct = [i.get("fix_correct") for i in data["items"] if i["condition"] == cond]
        out[cond] = {"n": len(times),
                     "mean_seconds": round(statistics.mean(times), 1) if times else None,
                     "median_seconds": round(statistics.median(times), 1) if times else None,
                     "self_rated_correct": sum(1 for c in correct if c)}
    if out["manual"]["mean_seconds"] and out["assisted"]["mean_seconds"]:
        out["reduction_pct"] = round(100 * (1 - out["assisted"]["mean_seconds"] / out["manual"]["mean_seconds"]), 1)
    return out


# ----------------------------------------------------------------------------- output
def results_markdown(res: dict) -> str:
    c, ci, d, r = res.get("controls", {}), res.get("ci", {}), res.get("detect", {}), res.get("review", {})
    rows = [f"| HIPAA controls automated | {c.get('implemented', '—')} of {c.get('defined', '—')} defined"
            f"{'' if c.get('evaluated_in_last_report') is None else f'; {c['evaluated_in_last_report']} evaluated in last report'} | 25+ |"]
    if ci.get("available"):
        rows.append(f"| CI pipeline duration | mean {ci['mean_seconds']}s, max {ci['max_seconds']}s over {ci['runs']} run(s) | < 180s |")
    else:
        rows.append("| CI pipeline duration | not measured yet | < 180s |")
    if d.get("available"):
        rt = "" if d["runtime_evaluated"] else " (log leaks only; runtime not evaluated)"
        rows.append(f"| Leak detection | {d['caught']} of {d['evaluated_leaks']} caught{rt}; "
                    f"precision {d['precision']}, recall {d['recall']} ({d['mode']}) | — |")
    else:
        rows.append("| Leak detection | not measured yet | — |")
    if r.get("available"):
        rows.append(f"| Review time per finding | manual {r['manual']['mean_seconds']}s vs assisted "
                    f"{r['assisted']['mean_seconds']}s (n={r['items']}) | — |")
    else:
        rows.append("| Review time per finding | not measured yet | — |")
    return ("# PHI Guard — measured results\n\n_Generated by `scripts/measure.py`; numbers come from "
            "artifacts in evidence/, not from this file._\n\n| Metric | Result | Goal |\n|---|---|---|\n"
            + "\n".join(rows) + "\n")


def print_summary(res: dict) -> None:
    print(results_markdown(res))
    d = res.get("detect") or {}
    if d.get("available"):
        print(f"per-entity recall: {d['per_entity_recall']}")
        print(f"missed: {d['missed']}")
        print(f"decoy false positives: {d['false_positives']['decoy_entities']}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["controls", "ci", "detect", "review", "all"])
    ap.add_argument("--cluster", action="store_true")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--engine", default="auto", choices=["auto", "presidio", "lite"])
    ap.add_argument("--alerts")
    ap.add_argument("--falco")
    args = ap.parse_args()

    res: dict = {}
    if args.command in ("controls", "all"):
        res["controls"] = measure_controls()
    if args.command in ("ci", "all"):
        res["ci"] = measure_ci()
    if args.command in ("detect", "all"):
        res["detect"] = measure_detect(args)
    if args.command in ("review", "all"):
        res["review"] = measure_review()

    EVIDENCE.mkdir(exist_ok=True)
    if args.command == "detect" and res["detect"].get("available"):
        (EVIDENCE / "detection-results.json").write_text(json.dumps(res["detect"], indent=2))
    if args.command == "all":
        (EVIDENCE / "results.json").write_text(json.dumps(res, indent=2))
        (EVIDENCE / "results.md").write_text(results_markdown(res))
        print_summary(res)
    else:
        printable = {k: ({kk: vv for kk, vv in v.items() if kk != "rows"} if isinstance(v, dict) else v)
                     for k, v in res.items()}
        print(json.dumps(printable, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
