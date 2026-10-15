"""Shared bits for the three sample EHR services: data loading, request ids, HTTP helper."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
import uuid
from functools import lru_cache
from pathlib import Path

from fastapi import FastAPI, Request

DATA_PATH = Path(os.getenv("PATIENT_DATA", Path(__file__).resolve().parent.parent / "data" / "patients.json"))
PATIENT_API_URL = os.getenv("PATIENT_API_URL", "http://patient-api:8000")


@lru_cache(maxsize=1)
def patients() -> dict[int, dict]:
    records = json.loads(DATA_PATH.read_text())
    if not all(r.get("synthetic") for r in records):
        raise RuntimeError("Refusing to load records that are not flagged synthetic=true")
    return {r["id"]: r for r in records}


@lru_cache(maxsize=1)
def by_member_id() -> dict[str, dict]:
    return {p["member_id"]: p for p in patients().values()}


def request_id(request: Request) -> str:
    return request.headers.get("x-request-id") or uuid.uuid4().hex[:16]


def fetch_patient(patient_id: int, rid: str) -> dict | None:
    """Cross-service call to patient-api (generates in-cluster traffic)."""
    req = urllib.request.Request(f"{PATIENT_API_URL}/patients/{patient_id}", headers={"x-request-id": rid})
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:  # noqa: S310 - fixed in-cluster URL
            return json.loads(resp.read())
    except (urllib.error.URLError, TimeoutError):
        return patients().get(patient_id)  # degrade gracefully when run standalone


def add_health(app: FastAPI) -> None:
    @app.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok"}

    @app.get("/readyz")
    def readyz() -> dict:
        return {"status": "ready", "patients": len(patients())}
