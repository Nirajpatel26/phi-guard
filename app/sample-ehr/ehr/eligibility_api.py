"""eligibility-api: checks coverage by health-plan member id."""
from __future__ import annotations

from fastapi import FastAPI, HTTPException, Request

from .common import add_health, by_member_id, fetch_patient, request_id
from .phi_logging import get_logger, log_patient_event

app = FastAPI(title="eligibility-api", version="0.1.0")
log = get_logger("eligibility-api")
add_health(app)


@app.get("/eligibility/{member_id}")
def check_eligibility(member_id: str, request: Request) -> dict:
    rid = request_id(request)
    match = by_member_id().get(member_id)
    if match is None:
        raise HTTPException(status_code=404, detail="member not found")
    patient = fetch_patient(match["id"], rid) or match  # cross-service hop
    log_patient_event(log, "eligibility_check", patient, rid)
    return {"member_id": member_id, "plan": patient["plan"], "eligible": True, "copay_usd": 25}
