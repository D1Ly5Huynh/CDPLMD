"""Watch fetch_virusshare_vt.py. Print only DONE/FAILED."""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

LOG = Path(r"C:\Users\tuonghk\CDPLMD\data\sources\fetch2.log")
META = Path(r"C:\Users\tuonghk\CDPLMD\data\paper25k\meta.json")
NPZ = Path(r"C:\Users\tuonghk\CDPLMD\data\paper25k\dataset.npz")
MAL = Path(r"C:\Users\tuonghk\CDPLMD\data\paper25k\malware_raw.jsonl")


def python_running() -> bool:
    try:
        out = subprocess.check_output(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-CimInstance Win32_Process | "
                "Where-Object { $_.CommandLine -like '*fetch_virusshare_vt.py*' } | "
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
    data = LOG.read_text(encoding="utf-8", errors="replace")
    return data[-8000:]


def main() -> int:
    while True:
        running = python_running()
        text = tail_text()
        meta_ok = False
        if META.exists():
            body = META.read_text(encoding="utf-8", errors="replace")
            meta_ok = (
                "VirusShare" in body
                and '"n_malware": 25000' in body
                and NPZ.exists()
            )
        if meta_ok and MAL.exists() and MAL.stat().st_size > 1000:
            if not running:
                print("DONE: paper-source 25k dataset written")
                return 0
        if "Traceback (most recent call last)" in text and not running:
            print("FAILED: traceback in fetch.log")
            return 1
        if not running and not meta_ok:
            print("FAILED: collector exited without 25k VirusShare/VT dataset")
            return 1
        time.sleep(20)


if __name__ == "__main__":
    sys.exit(main())
