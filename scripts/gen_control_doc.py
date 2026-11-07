#!/usr/bin/env python3
"""Regenerate docs/control-mapping.md from policies/mapping.yaml (single source of truth)."""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    m = yaml.safe_load((ROOT / "policies" / "mapping.yaml").read_text())
    lines = [
        "# HIPAA control mapping",
        "",
        "_Generated from `policies/mapping.yaml` by `scripts/gen_control_doc.py`. Edit the YAML, not this file._",
        "",
        f"Framework: {m['framework']}. {len(m['controls'])} controls.",
        "",
        "Mapping a technical check to a HIPAA implementation specification is an interpretation. "
        "Rows marked *indirect* support the safeguard without directly implementing it.",
        "",
        "| Citation | Safeguard | Controls |",
        "|---|---|---|",
    ]
    for cit, name in m["citations"].items():
        ids = [c["id"] for c in m["controls"] if c["citation"] == cit]
        lines.append(f"| {cit} | {name} | {len(ids)} ({', '.join(ids)}) |")
    lines += ["", "| Control | Citation | Severity | Scope | Engine | Check ID(s) | Title |",
              "|---|---|---|---|---|---|---|"]
    for c in m["controls"]:
        checks = ", ".join(c.get("checks", [c["id"]]))
        title = c["title"] + (" *(indirect)*" if c.get("mapping_strength") == "indirect" else "")
        lines.append(f"| {c['id']} | {c['citation']} | {c['severity']} | {c['scope']} | {c['engine']} | "
                     f"`{checks}` | {title} |")
    lines += ["", "**Engines.** `rego` controls live in `policies/rego/{terraform,kubernetes}/` (one file per "
              "safeguard family) and run under Conftest against the Terraform plan JSON and the Kubernetes "
              "manifests. `checkov` controls reuse built-in Checkov checks (`CKV_AWS_*`, `CKV_K8S_*`) or custom "
              "ones in `policies/checkov/` (`CKV_PHI_*`).", ""]
    (ROOT / "docs" / "control-mapping.md").write_text("\n".join(lines))
    print(f"wrote docs/control-mapping.md ({len(m['controls'])} controls)")


if __name__ == "__main__":
    main()
