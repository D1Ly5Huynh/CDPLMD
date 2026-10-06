"""Watch fetch_virusshare_vt.py. Print only DONE/FAILED."""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

LOG = Path(r"C:\Users\tuonghk\CDPLMD\data\sources\fetch5.log")
META = Path(r"C:\Users\tuonghk\CDPLMD\data\paper25k\meta.json")
NPZ = Path(r"C:\Users\tuonghk\CDPLMD\data\paper25k\dataset.npz")
MAL = Path(r"C:\Users\tuonghk\CDPLMD\data\paper25k\malware_raw.jsonl")
DIAG = Path(r"C:\Users\tuonghk\CDPLMD\data\sources\watch_collector.diag.log")


def python_running() -> bool:
    try:
        out = subprocess.check_output(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-CimInstance Win32_Process | "
                "Where-Object { $_.CommandLine -like '*fetch_virusshare_vt.py*' "
                "-and $_.CommandLine -notlike '*watch_collector*' } | "
                "Select-Object -ExpandProperty ProcessId",
            ],
            text=True,
            timeout=30,
        )
        return bool(out.strip())
    except Exception:
        return False


def tail_text() -> str:
    if not LOG.exists():
        return ""
    return LOG.read_text(encoding="utf-8", errors="replace")[-4000:]


def meta_ok() -> bool:
    if not META.exists() or not NPZ.exists() or not MAL.exists():
        return False
    try:
        body = json.loads(META.read_text(encoding="utf-8"))
    except Exception:
        return False
    src = str(body.get("malware_source") or "")
    return (
        body.get("n_malware") == 25000
        and ("MalDICT" in src or "ClarAVy" in src)
        and "not VirusShare" not in src
        and MAL.stat().st_size > 1000
    )


def main() -> int:
    started = time.time()
    while True:
        running = python_running()
        ok = meta_ok()
        elapsed = int(time.time() - started)
        DIAG.write_text(
            f"running={running} meta_ok={ok} elapsed={elapsed}\n",
            encoding="utf-8",
        )
        if ok and not running:
            print("DONE: paper-source 25k VirusShare+VT dataset written")
            return 0
        text = tail_text()
        if "Traceback (most recent call last)" in text and not running and elapsed > 15:
            print("FAILED: traceback in fetch3.log")
            return 1
        if not running and not ok and elapsed > 90:
            print("FAILED: collector exited without 25k VirusShare/VT dataset")
            return 1
        time.sleep(30)


if __name__ == "__main__":
    sys.exit(main())
