"""Scan a file of log lines offline (no cluster needed).

    python -m detector.presidio.scan_file evidence/seed_lines.log --out-dir evidence/offline --engine auto

Writes alerts.jsonl and masked.jsonl in the same format as the scanner service.
"""
from __future__ import annotations

import argparse
import json
import uuid
from pathlib import Path

from .engine import build_engine, scan_line


def scan_file(path: Path, out_dir: Path, engine_pref: str = "auto", spacy_model: str = "en_core_web_lg") -> dict:
    engine = build_engine(engine_pref, spacy_model)
    out_dir.mkdir(parents=True, exist_ok=True)
    n_lines = n_alerts = 0
    with (out_dir / "alerts.jsonl").open("w") as alerts, (out_dir / "masked.jsonl").open("w") as masked:
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            n_lines += 1
            r = scan_line(engine, line)
            src = {"namespace": "offline", "pod": "phi-leak-seeder-offline", "container": "seeder"}
            masked.write(json.dumps({"source": src, "masked": r.masked, "line_sha256": r.line_sha256,
                                     "phi": bool(r.findings)}) + "\n")
            if r.findings:
                n_alerts += 1
                alerts.write(json.dumps({
                    "alert_id": uuid.uuid4().hex[:12], "type": "phi_in_logs", "severity": r.severity,
                    "engine": r.engine, "source": src,
                    "entities": [{"type": f.entity, "score": f.score, "start": f.start, "end": f.end,
                                  "recognizer": f.recognizer} for f in r.findings],
                    "masked_line": r.masked, "line_sha256": r.line_sha256}) + "\n")
    return {"engine": engine.name, "lines": n_lines, "alerts": n_alerts, "out_dir": str(out_dir)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--out-dir", default="evidence/offline")
    ap.add_argument("--engine", choices=["auto", "presidio", "lite"], default="auto")
    ap.add_argument("--spacy-model", default="en_core_web_lg")
    args = ap.parse_args()
    print(json.dumps(scan_file(Path(args.file), Path(args.out_dir), args.engine, args.spacy_model)))


if __name__ == "__main__":
    main()
