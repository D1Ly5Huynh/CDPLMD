#!/usr/bin/env python3
"""VirusTotal before/after for one new PE. Does not touch results/lab_dataset."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from if_malevade.vt_client import VirusTotalClient  # noqa: E402


def _ask(label: str) -> str:
    if len(sys.argv) > 1 and label == "goc":
        return " ".join(sys.argv[1:]).strip().strip('"')
    return input(f"Duong dan file {label}: ").strip().strip('"')


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _slim(report: dict) -> dict:
    return {
        "ok": bool(report.get("ok")),
        "sha256": report.get("sha256") or report.get("upload_sha256"),
        "n": report.get("n"),
        "N": report.get("N"),
        "detection_rate": report.get("detection_rate"),
        "http_status": report.get("http_status"),
        "error": report.get("error"),
    }


def _report(client: VirusTotalClient, path: Path) -> dict:
    sha = _sha256(path)
    looked = client.report_hash(sha)
    if looked.get("ok") and looked.get("n") is not None:
        looked["source"] = "lookup"
        return looked
    uploaded = client.upload_file(path)
    finished = client.finish_upload(uploaded)
    finished["source"] = "upload"
    finished.setdefault("sha256", sha)
    return finished


def main() -> int:
    client = VirusTotalClient(rate_sleep=15.0)
    if not client.has_key():
        print("Thieu VT_API_KEY hoac data/vt.api", flush=True)
        return 2
    raw = _ask("goc")
    src = Path(raw)
    if not src.is_file():
        print(f"Khong thay file: {src}", flush=True)
        return 1
    mutant = ROOT / "demo_one" / f"{src.stem}.mut.exe"
    if not mutant.is_file():
        print(f"Chua co ban sua: {mutant}", flush=True)
        print("Chay truoc: python scripts\\demo\\mutate_one.py", flush=True)
        return 1

    print("Dang lay bao cao VirusTotal file goc...", flush=True)
    before = _report(client, src)
    print("Dang lay bao cao VirusTotal file da sua...", flush=True)
    after = _report(client, mutant)
    out = ROOT / "demo_one"
    out.mkdir(parents=True, exist_ok=True)
    (out / "vt_goc.json").write_text(json.dumps(_slim(before), indent=2), encoding="utf-8")
    (out / "vt_sua.json").write_text(json.dumps(_slim(after), indent=2), encoding="utf-8")

    n0 = before.get("n")
    n1 = after.get("n")
    evasion = None
    if isinstance(n0, (int, float)) and n0 > 0 and isinstance(n1, (int, float)):
        evasion = max(0.0, (float(n0) - float(n1)) / float(n0))
    pair = {
        "table6_before": _slim(before),
        "table6_after": _slim(after),
        "table7_evasion": evasion,
    }
    (out / "vt_pair.json").write_text(json.dumps(pair, indent=2), encoding="utf-8")
    print(
        f"Table 6 truoc: {before.get('n')}/{before.get('N')} = {before.get('detection_rate')}",
        flush=True,
    )
    print(
        f"Table 6 sau: {after.get('n')}/{after.get('N')} = {after.get('detection_rate')}",
        flush=True,
    )
    print(f"Table 7 evasion: {evasion}", flush=True)
    print(f"output {out / 'vt_pair.json'}", flush=True)
    return 0 if before.get("ok") and after.get("ok") else 4


if __name__ == "__main__":
    raise SystemExit(main())
