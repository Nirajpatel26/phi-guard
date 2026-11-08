"""Smoke test for the Python-only demo (scripts/demo_offline.py)."""
import json

from scripts import demo_offline


def test_demo_offline_runs_end_to_end(tmp_path, capsys):
    out = tmp_path / "demo"
    assert demo_offline.main(["--out-dir", str(out), "--engine", "lite", "--requests", "12"]) == 0
    data = json.loads((out / "demo-offline.json").read_text())
    assert data["app_logging"]["off_alerts"] == 0                    # compliant logging -> nothing to flag
    assert data["app_logging"]["on_alerts"] == 12                    # every leaky line is caught
    assert data["seeded"]["score"]["total_seeded_leaks"] == 50
    assert data["seeded"]["score"]["runtime_evaluated"] is False     # Falco runs only in the cluster
    assert data["gate"]["strict"]["exit_code"] == 1 and data["gate"]["with_waivers"]["exit_code"] == 0
    assert data["triage"] and all(t["triage"]["hipaa_citation"].startswith("45 CFR") for t in data["triage"])
    html = (out / "demo-offline.html").read_text()
    assert "PHI Guard" in html and "Lite engine" in html
    assert "Done in" in capsys.readouterr().out
