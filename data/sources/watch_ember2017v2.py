"""Watch EMBER 2017 v2 curl. Print only DONE/FAILED."""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

PART = Path(r"C:\Users\tuonghk\CDPLMD\data\sources\ember\ember_dataset_2017_2.tar.bz2.part")
FINAL = Path(r"C:\Users\tuonghk\CDPLMD\data\sources\ember\ember_dataset_2017_2.tar.bz2")
EXPECTED = 1_751_237_573
DIAG = Path(r"C:\Users\tuonghk\CDPLMD\data\sources\watch_ember2017v2.diag.log")


def curl_running() -> bool:
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
        "ember_dataset_2017_2" in ln and "watch_ember2017v2" not in ln
        for ln in blob.splitlines()
    )


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
        DIAG.write_text(f"size={n} running={running}\n", encoding="utf-8")
        if n == EXPECTED:
            print("DONE: ember 2017 v2 tarball complete")
            return 0
        if not running:
            print(f"FAILED: curl exited size={n}/{EXPECTED}")
            return 1
        if n == last:
            stall += 1
            if stall >= 40:
                print(f"FAILED: download stalled at {n}")
                return 1
        else:
            stall = 0
            last = n
        time.sleep(30)


if __name__ == "__main__":
    sys.exit(main())
