"""Watch EMBER curl resume. Print only DONE/FAILED."""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

PART = Path(r"C:\Users\tuonghk\CDPLMD\data\sources\ember\ember_dataset_2018_2.tar.bz2.part")
FINAL = Path(r"C:\Users\tuonghk\CDPLMD\data\sources\ember\ember_dataset_2018_2.tar.bz2")
LOG = Path(r"C:\Users\tuonghk\CDPLMD\data\sources\ember_curl.log")
EXPECTED = 1_696_539_273
DIAG = Path(r"C:\Users\tuonghk\CDPLMD\data\sources\watch_ember_curl.diag.log")


def curl_running() -> bool:
    try:
        out = subprocess.check_output(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-CimInstance Win32_Process | "
                "Where-Object { $_.CommandLine -like '*ember_dataset_2018_2.tar.bz2*' "
                "-and $_.Name -match 'curl' } | "
                "Select-Object -ExpandProperty ProcessId",
            ],
            text=True,
            timeout=30,
        )
        return bool(out.strip())
    except Exception:
        return False


def size_of() -> int:
    if FINAL.exists():
        return FINAL.stat().st_size
    if PART.exists():
        return PART.stat().st_size
    return 0


def main() -> int:
    last = -1
    stall = 0
    while True:
        n = size_of()
        running = curl_running()
        DIAG.write_text(
            f"size={n} expected={EXPECTED} running={running}\n", encoding="utf-8"
        )
        if n == EXPECTED:
            print("DONE: ember tarball complete")
            return 0
        if not running:
            tail = ""
            if LOG.exists():
                tail = LOG.read_text(encoding="utf-8", errors="replace")[-500:]
            print(f"FAILED: curl exited size={n}/{EXPECTED} {tail}")
            return 1
        if n == last:
            stall += 1
            if stall >= 40:
                print(f"FAILED: ember download stalled at {n} bytes")
                return 1
        else:
            stall = 0
            last = n
        time.sleep(30)


if __name__ == "__main__":
    sys.exit(main())
