#!/usr/bin/env python3
"""Explain failed (and waived) findings in plain English with a HIPAA citation and a fix diff.

    python -m triage.explain --findings evidence/compliance-report.json --out evidence/triage.json
    PHI_GUARD_LLM_PROVIDER=anthropic ANTHROPIC_API_KEY=... python -m triage.explain --limit 10

Guardrails
* The prompt includes only the mapping entry for the finding's own control, and the
  model must echo that control's id/citation/severity exactly.
* Output is parsed as JSON, validated with Pydantic, then checked against
  mapping.yaml. On failure the model gets one retry with the validation error;
  after that the deterministic mock answer is used and marked `source: fallback`.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import yaml
from pydantic import ValidationError

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from triage.providers import MockProvider, Provider, get_provider  # noqa: E402
from triage.schema import MappingMismatch, TriageResult, parse_llm_json, validate_against_mapping  # noqa: E402

SYSTEM_PROMPT = """You are a DevSecOps reviewer explaining infrastructure compliance findings
for a healthcare system that must meet the HIPAA Security Rule technical safeguards (45 CFR §164.312).

Rules you must follow:
1. Use ONLY the control given in CONTROL. Copy its id, citation and severity exactly. Never cite any
   other regulation, section, or control.
2. risk_summary: 2-4 plain-English sentences for an engineer: what is wrong with this specific
   resource, why it matters for PHI, and what an attacker or auditor would see. No marketing language.
3. suggested_fix: a minimal unified diff (lines starting with ---, +++, @@, +, -) in the format named
   by CONTROL.remediation.format, modifying the file and resource in FINDING. Base it on
   CONTROL.remediation.snippet. Do not invent unrelated changes.
4. confidence: "high" if the fix is mechanical, "medium" if it depends on context you cannot see,
   "low" if you are unsure.
5. Respond with a single JSON object and nothing else, with exactly these keys:
   finding_id, control_id, hipaa_citation, severity, risk_summary, suggested_fix {format, diff}, confidence.
"""


def build_user_prompt(finding: dict, control: dict, source_excerpt: str | None) -> str:
    payload = {
        "FINDING": {k: finding.get(k) for k in ("finding_id", "control_id", "resource", "file", "line",
                                                "engine", "check_id", "message", "status")},
        "CONTROL": {k: control[k] for k in ("id", "title", "citation", "safeguard", "severity", "risk",
                                            "remediation")},
    }
    text = json.dumps(payload, indent=2)
    if source_excerpt:
        text += f"\n\nSOURCE EXCERPT ({finding.get('file')}):\n{source_excerpt}"
    return text


def source_excerpt(finding: dict, context_lines: int = 25) -> str | None:
    if not finding.get("file") or not finding.get("line"):
        return None
    path = ROOT / finding["file"]
    if not path.exists():
        return None
    lines = path.read_text().splitlines()
    start = max(0, finding["line"] - 1)
    return "\n".join(f"{i + 1:4d}  {lines[i]}" for i in range(start, min(len(lines), start + context_lines)))


def explain_one(provider: Provider, finding: dict, control: dict, controls: dict) -> dict:
    t0 = time.monotonic()
    context = {"finding": finding, "control": control}
    user = build_user_prompt(finding, control, source_excerpt(finding))
    errors: list[str] = []
    for attempt in range(2):
        prompt = user if attempt == 0 else (
            user + f"\n\nYour previous answer was rejected: {errors[-1]}\nReturn corrected JSON only.")
        try:
            raw = provider.complete(SYSTEM_PROMPT, prompt, context)
            result = TriageResult.model_validate(parse_llm_json(raw))
            validate_against_mapping(result, finding, controls)
            return {**result.model_dump(), "source": provider.name, "model": provider.model,
                    "attempts": attempt + 1, "seconds": round(time.monotonic() - t0, 2)}
        except (ValidationError, MappingMismatch, ValueError, KeyError) as exc:
            errors.append(str(exc).splitlines()[0][:300])
        except Exception as exc:  # noqa: BLE001 - network/provider errors fall back too
            errors.append(f"provider error: {exc}"[:300])
            break
    fallback = TriageResult.model_validate(parse_llm_json(MockProvider().complete(SYSTEM_PROMPT, user, context)))
    return {**fallback.model_dump(), "source": "fallback", "model": MockProvider.model,
            "attempts": len(errors), "errors": errors, "seconds": round(time.monotonic() - t0, 2)}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--findings", default="evidence/compliance-report.json")
    ap.add_argument("--mapping", default="policies/mapping.yaml")
    ap.add_argument("--out", default="evidence/triage.json")
    ap.add_argument("--provider", help="mock | anthropic | openai (default: $PHI_GUARD_LLM_PROVIDER or mock)")
    ap.add_argument("--limit", type=int, default=0, help="explain at most N findings (0 = all)")
    ap.add_argument("--include-waived", action="store_true", default=True)
    args = ap.parse_args(argv)

    report = json.loads((ROOT / args.findings).read_text())
    mapping = yaml.safe_load((ROOT / args.mapping).read_text())
    controls = {c["id"]: {**c, "safeguard": mapping["citations"][c["citation"]]} for c in mapping["controls"]}
    statuses = {"FAIL", "WAIVED"} if args.include_waived else {"FAIL"}
    findings = [r for r in report["results"] if r["status"] in statuses]
    findings.sort(key=lambda r: ({"HIGH": 0, "MEDIUM": 1, "LOW": 2}[r["severity"]], r["control_id"], r["resource"]))
    if args.limit:
        findings = findings[: args.limit]

    provider, note = get_provider(args.provider)
    if note:
        print(f"note: {note}")
    print(f"triaging {len(findings)} finding(s) with provider={provider.name} model={provider.model}")
    out = []
    for f in findings:
        res = explain_one(provider, f, controls[f["control_id"]], controls)
        out.append({"finding": {k: f[k] for k in ("finding_id", "control_id", "resource", "file", "line",
                                                  "severity", "status", "message")}, "triage": res})
        flag = "" if res["source"] == provider.name else f"  [{res['source']}]"
        print(f"  {f['finding_id']} {f['control_id']:<11} {f['severity']:<6} {f['resource']}{flag}")

    dest = ROOT / args.out
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps({"provider": provider.name, "model": provider.model, "commit": report.get("commit"),
                                "count": len(out), "items": out}, indent=2))
    md = ["# PHI Guard — triage", ""]
    for item in out:
        t, f = item["triage"], item["finding"]
        md += [f"## {f['control_id']} · {f['resource']} ({t['severity']}, {f['status']})", "",
               f"**Citation:** {t['hipaa_citation']}  ", f"**Location:** {f['file']}:{f['line']}  ",
               f"**Source:** {t['source']} ({t['model']}), confidence {t['confidence']}", "",
               t["risk_summary"], "", f"```diff\n{t['suggested_fix']['diff']}\n```", ""]
    dest.with_suffix(".md").write_text("\n".join(md))
    print(f"wrote {args.out} and {Path(args.out).with_suffix('.md')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
