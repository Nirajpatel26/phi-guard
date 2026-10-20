"""PHI log scanner service. Fluent Bit's `http` output posts container log records here.

Endpoints
  POST /ingest   Fluent Bit records (JSON array or object); each record's `log` field is scanned
  POST /scan     {"text": "..."} -> scan result (debugging / demos)
  GET  /alerts   recent alerts (masked; never the raw line)
  GET  /stats    counters
  GET  /healthz

Output files (OUTPUT_DIR, default /data):
  alerts.jsonl   one alert per log line that contained PHI
  masked.jsonl   a masked copy of every scanned line (with source metadata)
"""
from __future__ import annotations

import json
import os
import threading
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from pydantic import BaseModel

from .engine import build_engine, scan_line

OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "/data"))
ENGINE = build_engine(os.getenv("PHI_ENGINE", "auto"), os.getenv("SPACY_MODEL", "en_core_web_lg"))

app = FastAPI(title="phi-scanner", version="0.1.0")
_lock = threading.Lock()
_recent: deque[dict] = deque(maxlen=500)
_stats = {"lines_scanned": 0, "alerts": 0, "engine": ENGINE.name}


def _write(name: str, record: dict) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with (OUTPUT_DIR / name).open("a") as fh:
        fh.write(json.dumps(record) + "\n")


def _source(record: dict) -> dict:
    k8s = record.get("kubernetes") or {}
    return {"namespace": k8s.get("namespace_name"), "pod": k8s.get("pod_name"),
            "container": k8s.get("container_name"), "stream": record.get("stream")}


def process_record(record: dict) -> dict | None:
    text = record.get("log") or record.get("message") or ""
    if not isinstance(text, str) or not text.strip():
        return None
    text = text.rstrip("\n")
    result = scan_line(ENGINE, text)
    now = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    src = _source(record)
    with _lock:
        _stats["lines_scanned"] += 1
        _write("masked.jsonl", {"ts": now, "source": src, "masked": result.masked,
                                "line_sha256": result.line_sha256, "phi": bool(result.findings)})
        if not result.findings:
            return None
        alert = {
            "alert_id": uuid.uuid4().hex[:12],
            "ts": now,
            "type": "phi_in_logs",
            "severity": result.severity,
            "engine": result.engine,
            "source": src,
            "entities": [{"type": f.entity, "score": f.score, "start": f.start, "end": f.end,
                          "recognizer": f.recognizer} for f in result.findings],
            "masked_line": result.masked,
            "line_sha256": result.line_sha256,
            "hipaa": "45 CFR §164.312(b) audit controls / §164.502 minimum necessary",
        }
        _stats["alerts"] += 1
        _recent.append(alert)
        _write("alerts.jsonl", alert)
        return alert


class ScanIn(BaseModel):
    text: str


@app.post("/ingest")
async def ingest(request: Request) -> dict:
    body: Any = await request.json()
    records = body if isinstance(body, list) else [body]
    alerts = [a for r in records if isinstance(r, dict) and (a := process_record(r))]
    return {"received": len(records), "alerts": len(alerts)}


@app.post("/scan")
def scan(payload: ScanIn) -> dict:
    r = scan_line(ENGINE, payload.text)
    return {"severity": r.severity, "entities": sorted({f.entity for f in r.findings}),
            "masked": r.masked, "engine": r.engine}


@app.get("/alerts")
def alerts(limit: int = 100) -> list[dict]:
    return list(_recent)[-limit:]


@app.get("/stats")
def stats() -> dict:
    return dict(_stats)


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "engine": ENGINE.name}
