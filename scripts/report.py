#!/usr/bin/env python3
"""Run Conftest + Checkov and merge their results into one HIPAA evidence report.

Outputs (default evidence/):
  compliance-report.json   machine-readable, consumed by triage/explain.py and measure.py
  compliance-report.md     human-readable, grouped by HIPAA citation
  compliance-report.html   same content, styled

Each result row carries: control id, HIPAA citation, severity, status
(PASS / FAIL / WAIVED), engine, check id, resource, file, line, commit SHA and
timestamp. PASS rows for Rego controls are derived from the in-scope resources
(plan JSON / manifests) that produced no failure, so the report shows coverage,
not just violations.

Typical use:
  python scripts/report.py                       # run tools, write report
  python scripts/report.py --fail-on HIGH        # exit 1 on unwaived HIGH failures (CI)
  python scripts/report.py --no-waivers          # ignore waivers (strict gate demo)
  python scripts/report.py --conftest-tf f.json --conftest-k8s g.json --checkov h.json   # use saved outputs
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
RULE_MSG = re.compile(r"^\[(?P<id>PHI-[A-Z0-9]+-\d+)\]\s+(?P<resource>.+?)(?:\s+@\s+(?P<file>\S+))?\s+::\s+(?P<message>.*)$")
TF_RESOURCE = re.compile(r'^\s*resource\s+"(?P<type>[\w-]+)"\s+"(?P<name>[\w-]+)"')
CLUSTER_SCOPED = {"Namespace", "ClusterRole", "ClusterRoleBinding", "PersistentVolume", "StorageClass"}
WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob", "Pod"}


# --------------------------------------------------------------------------- data
@dataclass
class Result:
    control_id: str
    title: str
    citation: str
    safeguard: str
    severity: str
    status: str               # PASS | FAIL | WAIVED
    engine: str               # conftest | checkov
    check_id: str
    resource: str
    file: str | None
    line: int | None
    message: str = ""
    finding_id: str = ""
    waiver: dict | None = None
    commit: str = ""
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.finding_id:
            digest = hashlib.sha1(f"{self.control_id}|{self.check_id}|{self.resource}".encode()).hexdigest()
            self.finding_id = f"F-{digest[:8]}"


@dataclass
class ToolRun:
    name: str
    ran: bool
    seconds: float = 0.0
    note: str = ""


@dataclass
class Context:
    mapping: dict
    plan: dict | None
    k8s_docs: list[dict] = field(default_factory=list)  # {kind, namespace, name, labels, ref, file, line, obj}
    tf_index: dict[str, tuple[str, int]] = field(default_factory=dict)


# --------------------------------------------------------------------------- helpers
def rel(p: str | Path) -> str:
    try:
        return str(Path(p).resolve().relative_to(ROOT))
    except ValueError:
        return str(p)


def load_mapping(path: Path) -> dict:
    data = yaml.safe_load(path.read_text())
    ids = [c["id"] for c in data["controls"]]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise ValueError(f"duplicate control ids in mapping: {sorted(dupes)}")
    for c in data["controls"]:
        if c["citation"] not in data["citations"]:
            raise ValueError(f"{c['id']}: citation {c['citation']!r} not declared in citations")
        c["safeguard"] = data["citations"][c["citation"]]
    return data


def commit_sha() -> str:
    if os.getenv("GITHUB_SHA"):
        return os.environ["GITHUB_SHA"]
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True,
                              check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "uncommitted"


def index_terraform(tf_dir: Path) -> dict[str, tuple[str, int]]:
    index: dict[str, tuple[str, int]] = {}
    for tf in sorted(tf_dir.rglob("*.tf")):
        if ".terraform" in tf.parts:
            continue
        for n, line in enumerate(tf.read_text().splitlines(), start=1):
            m = TF_RESOURCE.match(line)
            if m:
                index[f"{m['type']}.{m['name']}"] = (rel(tf), n)
    return index


def k8s_ref(kind: str, namespace: str | None, name: str) -> str:
    if kind in CLUSTER_SCOPED:
        return f"{kind}/{name}"
    return f"{kind}/{namespace or 'default'}/{name}"


def load_k8s_docs(paths: list[Path]) -> list[dict]:
    """Parse multi-document YAML, remembering the line each document starts on."""
    docs = []
    for path in paths:
        lines = path.read_text().splitlines(keepends=True)
        chunks: list[tuple[int, str]] = []
        start, buf = 1, []
        for n, line in enumerate(lines, start=1):
            if line.strip() == "---":
                chunks.append((start, "".join(buf)))
                start, buf = n + 1, []
            else:
                buf.append(line)
        chunks.append((start, "".join(buf)))
        for start_line, text in chunks:
            obj = yaml.safe_load(text) if text.strip() else None
            if not isinstance(obj, dict) or "kind" not in obj:
                continue
            # point at the `kind:` line rather than a leading comment
            offset = next((i for i, l in enumerate(text.splitlines()) if l.startswith("kind:")), 0)
            meta = obj.get("metadata") or {}
            docs.append({
                "kind": obj["kind"], "namespace": meta.get("namespace"), "name": meta.get("name", "?"),
                "labels": meta.get("labels") or {},
                "ref": k8s_ref(obj["kind"], meta.get("namespace"), meta.get("name", "?")),
                "file": rel(path), "line": start_line + offset, "obj": obj,
            })
    return docs


def k8s_files(k8s_dir: Path) -> list[Path]:
    return sorted(p for p in k8s_dir.rglob("*") if p.suffix in {".yaml", ".yml"})


# --------------------------------------------------------------------------- tool runners
def run(cmd: list[str], label: str) -> tuple[Any, float]:
    t0 = time.monotonic()
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    elapsed = time.monotonic() - t0
    out = proc.stdout.strip()
    try:
        data = json.loads(out) if out else []
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{label} did not return JSON (exit {proc.returncode}).\n"
                           f"stdout: {out[:800]}\nstderr: {proc.stderr[:800]}") from exc
    return data, elapsed


def run_conftest_tf(plan_path: Path) -> tuple[Any, float]:
    return run(["conftest", "test", "--all-namespaces", "--no-color", "--output", "json",
                "--policy", "policies/rego/terraform", str(plan_path)], "conftest (terraform)")


def run_conftest_k8s(files: list[Path]) -> tuple[Any, float]:
    return run(["conftest", "test", "--all-namespaces", "--combine", "--no-color", "--output", "json",
                "--policy", "policies/rego/kubernetes", *(rel(p) for p in files)], "conftest (kubernetes)")


def run_checkov(tf_dir: Path, k8s_dir: Path, check_ids: list[str]) -> tuple[Any, float]:
    return run(["checkov", "--directory", str(tf_dir), "--directory", str(k8s_dir),
                "--framework", "terraform", "kubernetes",
                "--external-checks-dir", "policies/checkov",
                "--check", ",".join(sorted(check_ids)),
                "--output", "json", "--compact", "--soft-fail"], "checkov")


# --------------------------------------------------------------------------- parsers
def parse_conftest(data: Any) -> list[dict]:
    """Conftest JSON -> [{control_id, resource, file, message}]."""
    failures = []
    for entry in data or []:
        for f in (entry.get("failures") or []):
            msg = f.get("msg", "")
            m = RULE_MSG.match(msg)
            if not m:
                failures.append({"control_id": "UNMAPPED", "resource": entry.get("filename", "?"),
                                 "file": entry.get("filename"), "message": msg})
                continue
            failures.append({"control_id": m["id"], "resource": m["resource"].strip(),
                             "file": m["file"], "message": m["message"].strip()})
    return failures


def normalize_checkov_resource(check_type: str, resource: str) -> str:
    if check_type == "kubernetes":
        parts = resource.split(".", 2)
        if len(parts) == 3:
            return k8s_ref(parts[0], parts[1], parts[2])
    return resource


def parse_checkov(data: Any) -> list[dict]:
    """Checkov JSON (dict for one framework, list for several) -> flat result rows."""
    reports = data if isinstance(data, list) else [data]
    rows = []
    for rep in reports:
        if not isinstance(rep, dict) or "results" not in rep:
            continue
        ctype = rep.get("check_type", "")
        for status_key, status in (("passed_checks", "PASS"), ("failed_checks", "FAIL")):
            for r in rep["results"].get(status_key, []) or []:
                path = r.get("file_abs_path") or r.get("repo_file_path") or r.get("file_path") or ""
                line_range = r.get("file_line_range") or [None]
                rows.append({
                    "check_id": r["check_id"], "status": status,
                    "resource": normalize_checkov_resource(ctype, r.get("resource", "?")),
                    "file": rel(path) if path else None, "line": line_range[0],
                    "message": r.get("check_name", ""),
                })
    return rows


# --------------------------------------------------------------------------- merge
def tf_in_scope(ctx: Context, control: dict) -> list[str]:
    if not ctx.plan:
        return []
    types = set(control.get("resource_types", []))
    tags = set(control.get("scope_tags", []))
    out = []
    for rc in ctx.plan.get("resource_changes", []):
        if rc["type"] not in types or rc["change"]["actions"] == ["delete"]:
            continue
        after = rc["change"].get("after") or {}
        if tags and (after.get("tags") or {}).get("data-classification") not in tags:
            continue
        out.append(rc["address"])
    return out


def k8s_in_scope(ctx: Context, control: dict) -> list[dict]:
    kinds = set(control.get("kinds", []))
    want = control.get("scope_labels") or {}
    return [d for d in ctx.k8s_docs
            if d["kind"] in kinds and all(d["labels"].get(k) == v for k, v in want.items())]


def locate(ctx: Context, resource: str, file_hint: str | None) -> tuple[str | None, int | None]:
    if resource in ctx.tf_index:
        return ctx.tf_index[resource]
    for d in ctx.k8s_docs:
        if d["ref"] == resource and (file_hint is None or d["file"] == rel(file_hint) or d["file"] == file_hint):
            return d["file"], d["line"]
    return (rel(file_hint) if file_hint else None), None


def build_results(ctx: Context, conftest_failures: list[dict], checkov_rows: list[dict],
                  tools: dict[str, ToolRun]) -> tuple[list[Result], list[dict]]:
    results: list[Result] = []
    coverage = []
    by_id: dict[str, list[dict]] = {}
    for f in conftest_failures:
        by_id.setdefault(f["control_id"], []).append(f)

    for c in ctx.mapping["controls"]:
        base = dict(control_id=c["id"], title=c["title"], citation=c["citation"],
                    safeguard=c["safeguard"], severity=c["severity"])
        evaluated = False
        if c["engine"] == "rego":
            tool = tools["conftest_tf" if c["scope"] == "terraform" else "conftest_k8s"]
            if tool.ran:
                evaluated = True
                failed = set()
                for f in by_id.get(c["id"], []):
                    file_, line = locate(ctx, f["resource"], f.get("file"))
                    results.append(Result(**base, status="FAIL", engine="conftest", check_id=c["id"],
                                          resource=f["resource"], file=file_, line=line, message=f["message"]))
                    failed.add(f["resource"])
                if c["scope"] == "terraform":
                    in_scope = [(a, *ctx.tf_index.get(a, (None, None))) for a in tf_in_scope(ctx, c)]
                else:
                    in_scope = [(d["ref"], d["file"], d["line"]) for d in k8s_in_scope(ctx, c)]
                for ref, file_, line in in_scope:
                    if ref not in failed:
                        results.append(Result(**base, status="PASS", engine="conftest", check_id=c["id"],
                                              resource=ref, file=file_, line=line, message="no violation"))
        else:
            if tools["checkov"].ran:
                rows = [r for r in checkov_rows if r["check_id"] in c["checks"]]
                evaluated = bool(rows)
                for r in rows:
                    results.append(Result(**base, status=r["status"], engine="checkov", check_id=r["check_id"],
                                          resource=r["resource"], file=r["file"], line=r["line"],
                                          message=r["message"]))
        coverage.append({"control_id": c["id"], "engine": c["engine"],
                         "checks": c.get("checks", [c["id"]]), "evaluated": evaluated})
    return results, coverage


def apply_waivers(results: list[Result], waivers: list[dict], today: date) -> list[dict]:
    expired = []
    active = []
    for w in waivers:
        exp = date.fromisoformat(str(w["expires"]))
        (expired if exp < today else active).append(w)
    for r in results:
        if r.status != "FAIL":
            continue
        for w in active:
            if fnmatch.fnmatch(r.control_id, w.get("control", "*")) and fnmatch.fnmatch(r.resource, w["resource"]):
                r.status = "WAIVED"
                r.waiver = {k: str(w[k]) for k in ("reason", "owner", "expires")}
                break
    return expired


def summarize(results: list[Result], mapping: dict, coverage: list[dict]) -> dict:
    per_control: dict[str, str] = {}
    for c in mapping["controls"]:
        rows = [r for r in results if r.control_id == c["id"]]
        if not rows:
            per_control[c["id"]] = "NOT_EVALUATED"
        elif any(r.status == "FAIL" for r in rows):
            per_control[c["id"]] = "FAIL"
        elif any(r.status == "WAIVED" for r in rows):
            per_control[c["id"]] = "WAIVED"
        else:
            per_control[c["id"]] = "PASS"
    sev = {s: sum(1 for r in results if r.status == "FAIL" and r.severity == s) for s in SEVERITY_ORDER}
    return {
        "controls_defined": len(mapping["controls"]),
        "controls_evaluated": sum(1 for c in coverage if c["evaluated"]),
        "control_status": per_control,
        "results_total": len(results),
        "pass": sum(1 for r in results if r.status == "PASS"),
        "fail": sum(1 for r in results if r.status == "FAIL"),
        "waived": sum(1 for r in results if r.status == "WAIVED"),
        "unwaived_fail_by_severity": sev,
    }


# --------------------------------------------------------------------------- render
def group_by_citation(results: list[Result], mapping: dict) -> list[dict]:
    groups = []
    for citation, safeguard in mapping["citations"].items():
        rows = sorted((r for r in results if r.citation == citation),
                      key=lambda r: ({"FAIL": 0, "WAIVED": 1, "PASS": 2}[r.status], SEVERITY_ORDER[r.severity],
                                     r.control_id, r.resource))
        groups.append({"citation": citation, "safeguard": safeguard, "rows": rows,
                       "fail": sum(r.status == "FAIL" for r in rows),
                       "waived": sum(r.status == "WAIVED" for r in rows),
                       "pass": sum(r.status == "PASS" for r in rows)})
    return groups


def render(report: dict, results: list[Result], mapping: dict, out_dir: Path) -> None:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    env = Environment(loader=FileSystemLoader(ROOT / "scripts" / "templates"),
                      autoescape=select_autoescape(["html"]), trim_blocks=True, lstrip_blocks=True)
    ctx = {"r": report, "groups": group_by_citation(results, mapping), "controls": mapping["controls"]}
    (out_dir / "compliance-report.md").write_text(env.get_template("report.md.j2").render(**ctx))
    (out_dir / "compliance-report.html").write_text(env.get_template("report.html.j2").render(**ctx))


# --------------------------------------------------------------------------- main
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mapping", default="policies/mapping.yaml")
    ap.add_argument("--waivers", default="policies/waivers.yaml")
    ap.add_argument("--no-waivers", action="store_true")
    ap.add_argument("--tf-dir", default="infra/terraform/aws")
    ap.add_argument("--k8s-dir", default="infra/k8s")
    ap.add_argument("--plan", default="build/tfplan.json")
    ap.add_argument("--conftest-tf", help="saved conftest JSON for the plan (skip running)")
    ap.add_argument("--conftest-k8s", help="saved conftest JSON for manifests (skip running)")
    ap.add_argument("--checkov", help="saved checkov JSON (skip running)")
    ap.add_argument("--out-dir", default="evidence")
    ap.add_argument("--fail-on", choices=["HIGH", "MEDIUM", "LOW", "NONE"], default="NONE")
    ap.add_argument("--banner", default="", help="note rendered at the top of the report")
    args = ap.parse_args(argv)

    t_start = time.monotonic()
    mapping = load_mapping(ROOT / args.mapping)
    tf_dir, k8s_dir = ROOT / args.tf_dir, ROOT / args.k8s_dir
    plan_path = ROOT / args.plan
    ctx = Context(mapping=mapping,
                  plan=json.loads(plan_path.read_text()) if plan_path.exists() else None,
                  k8s_docs=load_k8s_docs(k8s_files(k8s_dir)) if k8s_dir.exists() else [],
                  tf_index=index_terraform(tf_dir) if tf_dir.exists() else {})

    tools = {k: ToolRun(k, False) for k in ("conftest_tf", "conftest_k8s", "checkov")}
    conftest_failures: list[dict] = []
    checkov_rows: list[dict] = []

    # conftest: terraform plan
    if args.conftest_tf:
        conftest_failures += parse_conftest(json.loads(Path(args.conftest_tf).read_text()))
        tools["conftest_tf"] = ToolRun("conftest_tf", True, note=f"loaded {args.conftest_tf}")
    elif ctx.plan is None:
        tools["conftest_tf"].note = f"skipped: {args.plan} not found (run `make plan`)"
    elif shutil.which("conftest"):
        data, secs = run_conftest_tf(plan_path)
        conftest_failures += parse_conftest(data)
        tools["conftest_tf"] = ToolRun("conftest_tf", True, secs)
    else:
        tools["conftest_tf"].note = "skipped: conftest not installed"

    # conftest: kubernetes manifests
    if args.conftest_k8s:
        conftest_failures += parse_conftest(json.loads(Path(args.conftest_k8s).read_text()))
        tools["conftest_k8s"] = ToolRun("conftest_k8s", True, note=f"loaded {args.conftest_k8s}")
    elif shutil.which("conftest") and ctx.k8s_docs:
        data, secs = run_conftest_k8s(k8s_files(k8s_dir))
        conftest_failures += parse_conftest(data)
        tools["conftest_k8s"] = ToolRun("conftest_k8s", True, secs)
    else:
        tools["conftest_k8s"].note = "skipped: conftest not installed or no manifests"

    # checkov
    checkov_ids = sorted({cid for c in mapping["controls"] if c["engine"] == "checkov" for cid in c["checks"]})
    if args.checkov:
        checkov_rows = parse_checkov(json.loads(Path(args.checkov).read_text()))
        tools["checkov"] = ToolRun("checkov", True, note=f"loaded {args.checkov}")
    elif shutil.which("checkov"):
        data, secs = run_checkov(tf_dir, k8s_dir, checkov_ids)
        checkov_rows = parse_checkov(data)
        tools["checkov"] = ToolRun("checkov", True, secs)
    else:
        tools["checkov"].note = "skipped: checkov not installed"

    results, coverage = build_results(ctx, conftest_failures, checkov_rows, tools)
    unmapped = [f for f in conftest_failures if f["control_id"] == "UNMAPPED"]

    expired: list[dict] = []
    waivers_path = ROOT / args.waivers
    if not args.no_waivers and waivers_path.exists():
        expired = apply_waivers(results, (yaml.safe_load(waivers_path.read_text()) or {}).get("waivers", []),
                                date.today())

    sha, ts = commit_sha(), datetime.now(timezone.utc).isoformat(timespec="seconds")
    for r in results:
        r.commit, r.timestamp = sha, ts

    summary = summarize(results, mapping, coverage)
    report = {
        "tool": "phi-guard",
        "framework": mapping["framework"],
        "commit": sha,
        "generated_at": ts,
        "banner": args.banner,
        "waivers_applied": not args.no_waivers,
        "expired_waivers": expired,
        "tools": {k: asdict(v) for k, v in tools.items()},
        "duration_seconds": round(time.monotonic() - t_start, 2),
        "summary": summary,
        "coverage": coverage,
        "unmapped_failures": unmapped,
        "results": [asdict(r) for r in results],
    }

    out_dir = ROOT / args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "compliance-report.json").write_text(json.dumps(report, indent=2))
    render(report, results, mapping, out_dir)

    s = summary
    print(f"PHI Guard evidence report  commit={sha[:12]}  ({report['duration_seconds']}s)")
    for t in tools.values():
        print(f"  {t.name:<13} {'ran' if t.ran else 'SKIPPED'} {t.seconds:6.1f}s {t.note}")
    print(f"  controls: {s['controls_evaluated']}/{s['controls_defined']} evaluated | results: "
          f"{s['pass']} pass, {s['fail']} fail, {s['waived']} waived")
    print(f"  unwaived failures by severity: {s['unwaived_fail_by_severity']}")
    if unmapped:
        print(f"  WARNING: {len(unmapped)} conftest failures did not match the [PHI-XXX] message format")
    not_eval = [c["control_id"] for c in coverage if not c["evaluated"]]
    if not_eval:
        print(f"  not evaluated: {', '.join(not_eval)}")
    print(f"  wrote {rel(out_dir)}/compliance-report.{{json,md,html}}")

    if args.fail_on != "NONE":
        threshold = SEVERITY_ORDER[args.fail_on]
        blocking = [r for r in results if r.status == "FAIL" and SEVERITY_ORDER[r.severity] <= threshold]
        if blocking:
            print(f"GATE FAILED: {len(blocking)} unwaived finding(s) at or above {args.fail_on}:")
            for r in blocking[:20]:
                print(f"  - {r.control_id} {r.severity} {r.resource} ({r.file}:{r.line})")
            return 1
        print(f"GATE PASSED: no unwaived findings at or above {args.fail_on}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
