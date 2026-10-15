"""patient-api: source of synthetic patient records."""
from __future__ import annotations

from fastapi import FastAPI, HTTPException, Request

from .common import add_health, patients, request_id
from .phi_logging import get_logger, log_patient_event

app = FastAPI(title="patient-api", version="0.1.0")
log = get_logger("patient-api")
add_health(app)


@app.get("/patients/{patient_id}")
def get_patient(patient_id: int, request: Request) -> dict:
    patient = patients().get(patient_id)
    if patient is None:
        raise HTTPException(status_code=404, detail="patient not found")
    log_patient_event(log, "patient_read", patient, request_id(request))
    return patient


@app.get("/patients")
def search_patients(request: Request, name: str = "", limit: int = 10) -> list[dict]:
    rid = request_id(request)
    needle = name.lower()
    hits = [p for p in patients().values()
            if needle in f"{p['first_name']} {p['last_name']}".lower()][: max(1, min(limit, 50))]
    for p in hits:
        log_patient_event(log, "patient_search_hit", p, rid)
    return [{"id": p["id"], "mrn": p["mrn"], "name": f"{p['first_name']} {p['last_name']}"} for p in hits]
