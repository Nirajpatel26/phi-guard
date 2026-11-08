"""Triage schema validation and mapping guardrails."""
import json

import pytest
import yaml
from pydantic import ValidationError

from triage.explain import explain_one
from triage.providers import MockProvider, get_provider
from triage.schema import MappingMismatch, TriageResult, parse_llm_json, validate_against_mapping
from scripts.report import ROOT


@pytest.fixture(scope="module")
def controls():
    m = yaml.safe_load((ROOT / "policies" / "mapping.yaml").read_text())
    return {c["id"]: {**c, "safeguard": m["citations"][c["citation"]]} for c in m["controls"]}


@pytest.fixture()
def finding():
    return {"finding_id": "F-0a1b2c3d", "control_id": "PHI-ENC-02", "resource": "aws_db_instance.legacy_reporting",
            "file": "infra/terraform/aws/rds.tf", "line": 63, "engine": "checkov", "check_id": "CKV_AWS_16",
            "message": "Ensure all data stored in the RDS is securely encrypted at rest", "status": "FAIL",
            "severity": "HIGH"}


def valid_payload(finding, control):
    return json.loads(MockProvider().complete("", "", {"finding": finding, "control": control}))


def test_mock_output_validates_for_every_control(controls, finding):
    for cid, c in controls.items():
        f = {**finding, "control_id": cid, "severity": c["severity"]}
        result = TriageResult.model_validate(valid_payload(f, c))
        validate_against_mapping(result, f, controls)


def test_wrong_citation_rejected(controls, finding):
    p = valid_payload(finding, controls["PHI-ENC-02"])
    p["hipaa_citation"] = "45 CFR §164.308(a)(1)"   # administrative safeguard, not this control
    with pytest.raises(MappingMismatch):
        validate_against_mapping(TriageResult.model_validate(p), finding, controls)


def test_changed_severity_rejected(controls, finding):
    p = valid_payload(finding, controls["PHI-ENC-02"])
    p["severity"] = "LOW"
    with pytest.raises(MappingMismatch):
        validate_against_mapping(TriageResult.model_validate(p), finding, controls)


def test_invented_control_rejected(controls, finding):
    p = valid_payload(finding, controls["PHI-ENC-02"])
    p["control_id"] = "PHI-ENC-99"
    with pytest.raises(MappingMismatch):
        validate_against_mapping(TriageResult.model_validate(p), finding, controls)


@pytest.mark.parametrize("mutate", [
    lambda p: p.pop("risk_summary"),
    lambda p: p.update(extra_field="nope"),
    lambda p: p.update(risk_summary="too short"),
    lambda p: p["suggested_fix"].update(diff="storage_encrypted = true"),   # not a diff
    lambda p: p["suggested_fix"].update(format="json"),
    lambda p: p.update(confidence="certain"),
])
def test_schema_rejects_malformed_output(controls, finding, mutate):
    p = valid_payload(finding, controls["PHI-ENC-02"])
    mutate(p)
    with pytest.raises(ValidationError):
        TriageResult.model_validate(p)


def test_parse_llm_json_tolerates_fences_and_prose():
    assert parse_llm_json('Here you go:\n```json\n{"a": 1}\n```') == {"a": 1}


class BadThenGoodProvider:
    name, model = "fake", "fake-1"

    def __init__(self):
        self.calls = 0

    def complete(self, system, user, context):
        self.calls += 1
        payload = json.loads(MockProvider().complete(system, user, context))
        if self.calls == 1:
            payload["hipaa_citation"] = "45 CFR §164.530"
        return json.dumps(payload)


class AlwaysBadProvider:
    name, model = "fake", "fake-1"

    def complete(self, system, user, context):
        return "I think this is fine."


def test_retry_recovers_from_invalid_answer(controls, finding):
    p = BadThenGoodProvider()
    res = explain_one(p, finding, controls["PHI-ENC-02"], controls)
    assert res["source"] == "fake" and res["attempts"] == 2


def test_fallback_to_mock_after_two_bad_answers(controls, finding):
    res = explain_one(AlwaysBadProvider(), finding, controls["PHI-ENC-02"], controls)
    assert res["source"] == "fallback" and res["hipaa_citation"] == controls["PHI-ENC-02"]["citation"]


def test_missing_api_key_falls_back_to_mock(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    provider, note = get_provider("anthropic")
    assert provider.name == "mock" and "ANTHROPIC_API_KEY" in note
