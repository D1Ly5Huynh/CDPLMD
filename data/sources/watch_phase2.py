"""Watch EMBER 2017 parse + VirusShare hash download. Print only DONE/FAILED."""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

LOG = Path(r"C:\Users\tuonghk\CDPLMD\data\sources\fetch4.log")
VS = Path(r"C:\Users\tuonghk\CDPLMD\data\sources\virusshare")
STAMP2017 = Path(r"C:\Users\tuonghk\CDPLMD\data\sources\ember\ember_dataset.tar.bz2.parsed")
POOL = Path(r"C:\Users\tuonghk\CDPLMD\data\paper25k\malware_pool.jsonl")
DIAG = Path(r"C:\Users\tuonghk\CDPLMD\data\sources\watch_phase2.diag.log")
VS_MIN = 400


def cmdline_blob() -> str:
    try:
        return subprocess.check_output(
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
        return ""


def procs(needle: str) -> bool:
    blob = cmdline_blob()
    for line in blob.splitlines():
        if needle in line and "watch_phase2" not in line:
            return True
    return False


def vs_count() -> int:
    if not VS.exists():
        return 0
    return sum(1 for p in VS.glob("VirusShare_*.md5") if p.stat().st_size > 1000)


def log_tail() -> str:
    if not LOG.exists():
        return ""
    return LOG.read_text(encoding="utf-8", errors="replace")[-4000:]


def main() -> int:
    started = time.time()
    while True:
        elapsed = int(time.time() - started)
        parse_run = procs("fetch_virusshare_vt.py")
        vs_run = procs("download_virusshare_packs")
        n_vs = vs_count()
        text = log_tail()
        parse_done = STAMP2017.exists() and not parse_run
        vs_done = n_vs >= VS_MIN and not vs_run
        DIAG.write_text(
            f"elapsed={elapsed} parse_run={parse_run} vs_run={vs_run} "
            f"n_vs={n_vs} stamp2017={STAMP2017.exists()}\n",
            encoding="utf-8",
        )
        if "Traceback (most recent call last)" in text and not parse_run and elapsed > 20:
            print("FAILED: traceback in fetch4.log")
            return 1
        if parse_done and vs_done:
            print("DONE: EMBER 2017 parsed and VirusShare hash packs downloaded")
            return 0
        if not parse_run and not STAMP2017.exists() and elapsed > 120:
            if "pool updated" in text or "skip writing" in text:
                print("DONE: pool updated without 2017 stamp")
                return 0
            print("FAILED: 2017 parser exited without stamp")
            return 1
        if not vs_run and n_vs < VS_MIN and elapsed > 180:
            print(f"FAILED: VirusShare download exited with {n_vs} packs")
            return 1
        time.sleep(30)


if __name__ == "__main__":
    sys.exit(main())
