"""Runs INSIDE the seeder Job (mounted from a ConfigMap). Standard library only.

Prints each planned log line to stdout, then triggers the runtime events. Each
runtime event runs as its own child process with the SEED-Rnnn marker in argv,
so Falco's %proc.cmdline carries the marker for ground-truth matching.
"""
import json
import subprocess
import sys
import time

EGRESS_CODE = (
    "import socket,sys\n"
    "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n"
    "s.setblocking(False)\n"
    "s.connect_ex((sys.argv[1],int(sys.argv[2])))\n"
    "s.close()\n"
)
SECRET_CODE = "import sys\nopen(sys.argv[1]).read()\n"


def main(plan_path: str) -> None:
    plan = json.load(open(plan_path))
    for line in plan["log_lines"]:
        print(line["text"], flush=True)
        time.sleep(0.15)

    time.sleep(2)
    for ev in plan["runtime"]:
        if ev["kind"] == "egress":
            cmd = [sys.executable, "-c", EGRESS_CODE, ev["ip"], str(ev["port"]), ev["marker"]]
        elif ev["kind"] == "shell":
            cmd = ["sh", "-c", "true", ev["marker"]]
        elif ev["kind"] == "secret_read":
            cmd = [sys.executable, "-c", SECRET_CODE, ev["path"], ev["marker"]]
        else:
            continue
        subprocess.run(cmd, check=False, timeout=10)
        print(f"runtime event {ev['id']} executed", flush=True)
        time.sleep(0.5)
    time.sleep(5)  # let the log shipper catch up before the container exits


if __name__ == "__main__":
    main(sys.argv[1])
