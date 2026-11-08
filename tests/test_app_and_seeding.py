"""Synthetic data, LEAK_MODE logging and the 50-leak seeding contract."""
import json
import re

from ehr import phi_logging
from scripts import seed_leaks
from detector.presidio.recognizers import npi_valid, synthetic_ssn_valid


def test_patients_are_synthetic_and_well_formed(patients):
    assert len(patients) == 200
    for p in patients:
        assert p["synthetic"] is True
        assert synthetic_ssn_valid(p["ssn"])                  # 9xx area: never an issued SSN
        assert re.fullmatch(r"MRN-\d{7}", p["mrn"])
        assert re.fullmatch(r"[A-Z]{3}\d{9}", p["member_id"])
        assert npi_valid(p["pcp_npi"])
        assert p["email"].endswith(("@example.com", "@example.org"))
        assert "555-01" in p["phone"]


def test_generation_is_reproducible():
    from scripts.generate_patients import generate
    assert generate(5, 42) == generate(5, 42)


def test_leak_mode_off_logs_no_phi(monkeypatch, patients):
    monkeypatch.setenv("LEAK_MODE", "off")
    log = phi_logging.get_logger("test-off")
    p = patients[0]
    for _ in range(10):
        line = phi_logging.log_patient_event(log, "patient_read", p, "rid1")
        for value in (p["first_name"], p["last_name"], p["ssn"], p["mrn"], p["member_id"], p["pcp_npi"], p["dob"]):
            assert value not in line
        assert "patient_ref=" in line


def test_leak_mode_on_rotates_formats(monkeypatch, patients):
    monkeypatch.setenv("LEAK_MODE", "on")
    log = phi_logging.get_logger("test-on")
    p = patients[1]
    lines = {phi_logging.log_patient_event(log, "patient_read", p, "rid2") for _ in range(16)}
    assert len(lines) == len(phi_logging.leak_formats("patient_read", p, "rid2"))
    joined = "\n".join(lines)
    assert p["ssn"] in joined and p["mrn"] in joined and p["member_id"] in joined and p["pcp_npi"] in joined
    assert any(line.startswith("{") for line in lines)              # structured JSON variant
    assert p["ssn"].replace("-", "") in joined                       # compact SSN variant


def test_seed_plan_has_exactly_50_labelled_leaks(patients):
    plan, truth = seed_leaks.build_plan(patients, 2026)
    assert truth["total_leaks"] == 50
    assert len(truth["log_leaks"]) == 40 and len(truth["runtime_leaks"]) == 10
    assert len(truth["decoys"]) == 30
    assert len(plan["log_lines"]) == 70
    ids = [line["id"] for line in plan["log_lines"]]
    assert len(set(ids)) == 70
    assert all(line["text"].endswith(f"rid=seed-{line['id']}") for line in plan["log_lines"])
    kinds = [r["kind"] for r in truth["runtime_leaks"]]
    assert kinds.count("egress") == 6 and kinds.count("shell") == 2 and kinds.count("secret_read") == 2
    assert all(r["ip"].startswith("203.0.113.") for r in truth["runtime_leaks"] if r["kind"] == "egress")


def test_decoys_contain_no_patient_values(patients):
    plan, truth = seed_leaks.build_plan(patients, 2026)
    decoy_ids = {d["id"] for d in truth["decoys"]}
    decoy_text = "\n".join(line["text"] for line in plan["log_lines"] if line["id"] in decoy_ids)
    for p in patients:
        for v in (p["ssn"], p["mrn"], p["member_id"], p["email"]):
            assert v not in decoy_text


def test_seeder_job_manifest_is_pss_restricted_friendly():
    m = seed_leaks.job_manifest("phi-guard/sample-ehr:0.1.0")
    for needle in ("runAsNonRoot: true", "allowPrivilegeEscalation: false", "RuntimeDefault",
                   'drop: ["ALL"]', "readOnlyRootFilesystem: true", "automountServiceAccountToken: false"):
        assert needle in m


def test_measure_scoring_on_synthetic_alerts(patients):
    from scripts.measure import score_detection
    _, truth = seed_leaks.build_plan(patients, 2026)
    src = {"pod": "phi-leak-seeder-abc"}
    alerts = [{"source": src, "engine": "lite", "masked_line": f"x rid=seed-{l['id']}",
               "entities": [{"type": t} for t in l["expected_entities"]]} for l in truth["log_leaks"][:30]]
    alerts.append({"source": src, "engine": "lite", "masked_line": "y rid=seed-D001", "entities": [{"type": "PERSON"}]})
    falco = [{"rule": r["expected_rule"], "tags": ["phi_guard"],
              "output_fields": {"proc.cmdline": f"python -c x {r['marker']}", "k8s.pod.name": "phi-leak-seeder-abc"}}
             for r in truth["runtime_leaks"][:8]]
    res = score_detection(truth, alerts, None, falco)
    assert res["caught"] == 38 and res["evaluated_leaks"] == 50
    assert res["false_positives"]["decoys_flagged"] == 1
    assert res["recall"] == round(38 / 50, 3) and res["precision"] == round(38 / 39, 3)
    json.dumps(res)  # serialisable
