"""Logging helpers for the sample EHR services.

LEAK_MODE=off (default, compliant): logs carry only a request id and a salted hash
of the patient id. LEAK_MODE=on: the same call sites log synthetic PHI in a
rotating set of formats (plain text, JSON, key=value, URL query strings,
tracebacks with record dumps, compact SSNs, alternative date formats) so the
detector has to cope with realistic variety instead of a single regex-friendly
shape.

This module has no FastAPI dependency so it can be unit-tested on its own.
"""
from __future__ import annotations

import hashlib
import itertools
import json
import logging
import os
import sys
from datetime import date

_counter = itertools.count()


def leak_mode() -> bool:
    return os.getenv("LEAK_MODE", "off").strip().lower() in {"on", "true", "1", "yes"}


def patient_ref(patient_id: int | str) -> str:
    salt = os.getenv("LOG_HASH_SALT", "phi-guard-demo-salt")
    return hashlib.sha256(f"{salt}:{patient_id}".encode()).hexdigest()[:12]


def get_logger(service: str) -> logging.Logger:
    logger = logging.getLogger(service)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s " + service + " %(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger


def _dob_variants(dob_iso: str) -> list[str]:
    d = date.fromisoformat(dob_iso)
    return [d.isoformat(), d.strftime("%m/%d/%Y"), d.strftime("%b %d, %Y")]


def leak_formats(event: str, patient: dict, request_id: str) -> list[str]:
    """All the ways a careless developer might log this patient. Pure function."""
    name = f"{patient['first_name']} {patient['last_name']}"
    iso, us, long_ = _dob_variants(patient["dob"])
    ssn_compact = patient["ssn"].replace("-", "")
    return [
        f"{event} rid={request_id} patient name={name} dob={iso}",
        json.dumps({"event": event, "rid": request_id, "patient": {
            "name": name, "ssn": patient["ssn"], "mrn": patient["mrn"]}}),
        f"{event} rid={request_id} mrn={patient['mrn']} member_id={patient['member_id']} pcp_npi={patient['pcp_npi']}",
        f"{event} rid={request_id} GET /patients/search?name={patient['first_name']}+{patient['last_name']}&dob={iso}",
        (f"{event} rid={request_id} ERROR KeyError('plan') while processing record "
         f"{{'mrn': '{patient['mrn']}', 'name': '{name}', 'ssn': '{patient['ssn']}'}}"),
        f"{event} rid={request_id} verifying identity ssn={ssn_compact} date of birth {us}",
        f"{event} rid={request_id} contact on file phone={patient['phone']} email={patient['email']}",
        f"{event} rid={request_id} subscriber {patient['member_id']} born {long_} plan='{patient['plan']}'",
    ]


def log_patient_event(logger: logging.Logger, event: str, patient: dict, request_id: str) -> str:
    """Log an event about a patient. Returns the line that was logged (for tests)."""
    if leak_mode():
        formats = leak_formats(event, patient, request_id)
        line = formats[next(_counter) % len(formats)]
    else:
        line = f"{event} rid={request_id} patient_ref={patient_ref(patient['id'])}"
    logger.info(line)
    return line
