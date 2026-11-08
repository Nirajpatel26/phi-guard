"""Report merging: Conftest + Checkov -> one evidence report grouped by HIPAA citation."""
import json
from datetime import date

import pytest

from scripts import report


@pytest.fixture()
def run_report(tmp_path, fixtures):
    def _run(*extra):
        out = tmp_path / "evidence"
        rc = report.main([
            "--plan", str(fixtures / "tfplan_min.json"),
            "--conftest-tf", str(fixtures / "conftest_tf.json"),
            "--conftest-k8s", str(fixtures / "conftest_k8s.json"),
            "--checkov", str(fixtures / "checkov.json"),
            "--out-dir", str(out), *extra,
        ])
        return rc, json.loads((out / "compliance-report.json").read_text()), out
    return _run


def test_mapping_has_25_plus_controls_and_valid_citations():
    m = report.load_mapping(report.ROOT / "policies" / "mapping.yaml")
    assert len(m["controls"]) >= 25
    cited = {c["citation"] for c in m["controls"]}
    assert cited == set(m["citations"])  # every §164.312 subsection in scope is covered


def test_parse_conftest_extracts_ids_resources_and_files(load_fixture):
    rows = report.parse_conftest(load_fixture("conftest_k8s.json"))
    first = rows[0]
    assert first["control_id"] == "PHI-K8S-02"
    assert first["resource"] == "Deployment/phi-reporting/report-exporter"
    assert first["file"] == "infra/k8s/legacy/reporting-stack.yaml"
    assert rows[-1]["control_id"] == "UNMAPPED"


def test_parse_checkov_handles_list_and_normalises_k8s_resources(load_fixture):
    rows = report.parse_checkov(load_fixture("checkov.json"))
    k8s = [r for r in rows if r["check_id"] == "CKV_K8S_16"]
    assert {r["resource"] for r in k8s} == {"Deployment/phi/patient-api", "Deployment/phi-reporting/report-exporter"}
    single = report.parse_checkov(load_fixture("checkov.json")[0])  # dict form (one framework)
    assert len(single) == 4


def test_merge_produces_pass_fail_with_locations(run_report):
    rc, rep, _ = run_report("--no-waivers")
    assert rc == 0
    rows = rep["results"]
    fail = next(r for r in rows if r["control_id"] == "PHI-AC-01" and r["status"] == "FAIL")
    assert fail["resource"] == "aws_s3_bucket.legacy_exports"
    assert fail["file"] == "infra/terraform/aws/s3.tf" and isinstance(fail["line"], int)
    # PASS evidence derived for in-scope resources without a failure
    assert any(r["control_id"] == "PHI-AC-01" and r["status"] == "PASS" and r["resource"] == "aws_s3_bucket.phi_records"
               for r in rows)
    # scope_tags: access_logs (internal) is out of scope for PHI-ENC-01
    assert not any(r["control_id"] == "PHI-ENC-01" and r["resource"] == "aws_s3_bucket.access_logs" for r in rows)
    # every row carries commit + timestamp + citation
    assert all(r["commit"] and r["timestamp"] and r["citation"].startswith("45 CFR") for r in rows)


def test_k8s_failure_located_to_manifest_line(run_report):
    _, rep, _ = run_report("--no-waivers")
    row = next(r for r in rep["results"] if r["control_id"] == "PHI-K8S-08")
    assert row["file"] == "infra/k8s/legacy/reporting-stack.yaml"
    lines = (report.ROOT / row["file"]).read_text().splitlines()
    assert lines[row["line"] - 1].startswith("kind: Ingress")


def test_checkov_controls_evaluated_and_unevaluated_reported(run_report):
    _, rep, _ = run_report("--no-waivers")
    status = rep["summary"]["control_status"]
    assert status["PHI-ENC-02"] == "FAIL"           # CKV_AWS_16 failed on legacy_reporting
    assert status["PHI-INT-03"] == "FAIL"           # custom CKV_PHI_AWS_1
    assert status["PHI-AU-01"] == "NOT_EVALUATED"   # CKV_AWS_67 absent from fixture
    assert rep["unmapped_failures"]


def test_fail_on_high_gate_and_waivers(run_report):
    rc_strict, rep_strict, _ = run_report("--no-waivers", "--fail-on", "HIGH")
    assert rc_strict == 1 and rep_strict["summary"]["unwaived_fail_by_severity"]["HIGH"] > 0
    rc_waived, rep_waived, _ = run_report("--fail-on", "HIGH")
    assert rc_waived == 0
    waived = [r for r in rep_waived["results"] if r["status"] == "WAIVED"]
    assert waived and all(r["waiver"]["reason"] for r in waived)


def test_expired_waiver_is_ignored():
    r = report.Result(control_id="PHI-AC-01", title="t", citation="c", safeguard="s", severity="HIGH",
                      status="FAIL", engine="conftest", check_id="PHI-AC-01", resource="aws_s3_bucket.legacy_x",
                      file=None, line=None)
    expired = report.apply_waivers([r], [{"control": "*", "resource": "aws_*.legacy*", "reason": "x",
                                          "owner": "o", "expires": "2020-01-01"}], date(2026, 1, 1))
    assert r.status == "FAIL" and len(expired) == 1


def test_markdown_and_html_grouped_by_citation(run_report):
    _, _, out = run_report()
    md = (out / "compliance-report.md").read_text()
    html = (out / "compliance-report.html").read_text()
    for heading in ("45 CFR §164.312(a)(1) — Access control", "45 CFR §164.312(e)(2)(ii)"):
        assert heading in md
    assert "<table>" in html and "PHI-AC-01" in html
