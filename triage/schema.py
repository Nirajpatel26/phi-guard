"""Output schema for triage results, plus validation against policies/mapping.yaml.

The schema stops malformed output; `validate_against_mapping` stops *plausible but
wrong* output: an invented control, a citation that doesn't belong to the
control, a severity the model decided to change, or a fix in the wrong language.
"""
from __future__ import annotations

import json
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class SuggestedFix(BaseModel):
    model_config = ConfigDict(extra="forbid")
    format: Literal["terraform", "yaml"]
    diff: str = Field(min_length=10, max_length=4000)

    @field_validator("diff")
    @classmethod
    def looks_like_unified_diff(cls, v: str) -> str:
        lines = v.splitlines()
        if not any(line.startswith("+") and not line.startswith("+++") for line in lines):
            raise ValueError("diff must contain at least one added line starting with '+'")
        if not any(line.startswith(("---", "@@")) for line in lines):
            raise ValueError("diff must use unified diff headers ('---'/'+++' or '@@')")
        return v


class TriageResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    finding_id: str = Field(pattern=r"^F-[0-9a-f]{8}$")
    control_id: str = Field(pattern=r"^PHI-[A-Z0-9]+-\d{2}$")
    hipaa_citation: str
    severity: Literal["HIGH", "MEDIUM", "LOW"]
    risk_summary: str = Field(min_length=40, max_length=1200)
    suggested_fix: SuggestedFix
    confidence: Literal["high", "medium", "low"]


class MappingMismatch(ValueError):
    pass


def validate_against_mapping(result: TriageResult, finding: dict, controls: dict[str, dict]) -> None:
    control = controls.get(result.control_id)
    if control is None:
        raise MappingMismatch(f"control_id {result.control_id} is not in mapping.yaml")
    if result.control_id != finding["control_id"]:
        raise MappingMismatch(f"control_id {result.control_id} does not match finding {finding['control_id']}")
    if result.finding_id != finding["finding_id"]:
        raise MappingMismatch(f"finding_id {result.finding_id} does not match {finding['finding_id']}")
    if result.hipaa_citation != control["citation"]:
        raise MappingMismatch(f"citation {result.hipaa_citation!r} != mapping {control['citation']!r}")
    if result.severity != control["severity"]:
        raise MappingMismatch(f"severity {result.severity} != mapping {control['severity']}")
    if result.suggested_fix.format != control["remediation"]["format"]:
        raise MappingMismatch(f"fix format {result.suggested_fix.format} != {control['remediation']['format']}")


_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)


def parse_llm_json(text: str) -> dict:
    """Extract the first JSON object from a model response (tolerates code fences / prose)."""
    cleaned = _FENCE.sub("", text.strip())
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("no JSON object in model output")
    return json.loads(cleaned[start:end + 1])
