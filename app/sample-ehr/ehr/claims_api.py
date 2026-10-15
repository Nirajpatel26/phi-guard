"""claims-api: submits and reads claims; looks patients up through patient-api."""
from __future__ import annotations

import uuid

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from .common import add_health, fetch_patient, patients, request_id
from .phi_logging import get_logger, log_patient_event

app = FastAPI(title="claims-api", version="0.1.0")
log = get_logger("claims-api")
add_health(app)

_submitted: dict[str, dict] = {}


class ClaimIn(BaseModel):
    patient_id: int
    cpt: str = Field(pattern=r"^\d{5}$")
    icd10: str
    billed_amount: float = Field(gt=0, lt=100_000)


@app.post("/claims", status_code=201)
def submit_claim(claim: ClaimIn, request: Request) -> dict:
    rid = request_id(request)
    patient = fetch_patient(claim.patient_id, rid)
    if patient is None:
        raise HTTPException(status_code=404, detail="patient not found")
    claim_id = f"CLM-NEW-{uuid.uuid4().hex[:8]}"
    _submitted[claim_id] = {"claim_id": claim_id, **claim.model_dump()}
    log_patient_event(log, "claim_submitted", patient, rid)
    return {"claim_id": claim_id, "status": "received"}


@app.get("/claims/{claim_id}")
def get_claim(claim_id: str, request: Request) -> dict:
    rid = request_id(request)
    if claim_id in _submitted:
        return _submitted[claim_id]
    for p in patients().values():
        for c in p["claims"]:
            if c["claim_id"] == claim_id:
                log_patient_event(log, "claim_read", p, rid)
                return {**c, "patient_id": p["id"]}
    raise HTTPException(status_code=404, detail="claim not found")
