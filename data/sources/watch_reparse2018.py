"""Watch EMBER 2018 reparse. Print only DONE/FAILED."""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

LOG = Path(r"C:\Users\tuonghk\CDPLMD\data\sources\fetch7.log")
STAMP = Path(r"C:\Users\tuonghk\CDPLMD\data\sources\ember\ember_dataset_2018_2.tar.bz2.parsed")
DIAG = Path(r"C:\Users\tuonghk\CDPLMD\data\sources\watch_reparse2018.diag.log")


def running() -> bool:
    try:
        blob = subprocess.check_output(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-CimInstance Win32_Process | ForEach-Object { $_.CommandLine }",
            ],
            text=True,
            timeout=30,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        return False
    return any(
        "fetch_virusshare_vt.py" in ln and "watch_reparse" not in ln
        for ln in blob.splitlines()
    )


def main() -> int:
    started = time.time()
    while True:
        elapsed = int(time.time() - started)
        run = running()
        text = LOG.read_text(encoding="utf-8", errors="replace")[-3000:] if LOG.exists() else ""
        DIAG.write_text(f"elapsed={elapsed} run={run} stamp={STAMP.exists()}\n", encoding="utf-8")
        if STAMP.exists() and not run:
            print("DONE: EMBER 2018 reparsed")
            return 0
        if "Traceback (most recent call last)" in text and not run and elapsed > 20:
            print("FAILED: traceback in fetch7.log")
            return 1
        if not run and not STAMP.exists() and elapsed > 90:
            print("FAILED: parser exited without 2018 stamp")
            return 1
        time.sleep(30)


if __name__ == "__main__":
    sys.exit(main())
