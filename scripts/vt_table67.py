#!/usr/bin/env python3
"""VirusTotal Table 6–7 (IF-MalEvade eqs. 3–4).

Originals: GET /files/{sha256} — no bytes uploaded.
Mutants: POST /files if matching PE exists under data/pe/malware/.

  set VT_API_KEY=...
  python scripts/vt_table67.py --eval-n 500
  python scripts/vt_table67.py --eval-n 5   # smoke
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from if_malevade.config import Config  # noqa: E402
from if_malevade.data import load_paper_dataset  # noqa: E402
from if_malevade.metrics import save_json  # noqa: E402
from if_malevade.vt_client import VirusTotalClient, table6_7  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--eval-n", type=int, default=500)
    p.add_argument("--upload-pe", action="store_true", help="upload local PE mutants if present")
    args = p.parse_args()
    cfg = Config()
    client = VirusTotalClient(rate_sleep=cfg.vt_rate_sleep)
    if not client.has_key():
        print("missing VT_API_KEY (or data/vt.api)")
        return 2
    data = load_paper_dataset(ROOT)
    sha_arr = data.get("sha256_test")
    sha = [str(x) for x in (sha_arr if sha_arr is not None else []) if str(x)]
    sha = sha[: args.eval_n]
    if not sha:
        print("dataset.npz has no sha256_test — rebuild paper25k npz")
        return 2
    out = ROOT / "results"
    jsonl = out / "vt_original_reports.jsonl"
    done: dict[str, dict] = {}
    if jsonl.exists():
        for line in jsonl.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            if rec.get("sha256"):
                done[str(rec["sha256"])] = rec
        n_ok = sum(1 for r in done.values() if r.get("ok"))
        print(f"resume {n_ok} ok / {len(done)} rows in {jsonl}")
    rows = []
    with jsonl.open("a", encoding="utf-8") as f:
        for i, h in enumerate(sha, 1):
            prev = done.get(h)
            if prev and prev.get("ok"):
                rows.append(prev)
                continue
            rec = client.report_hash(h)
            if rec.get("http_status") == 429:
                print(f"{i}/{len(sha)} RATE_LIMIT sleep 60")
                time.sleep(60)
                rec = client.report_hash(h)
            rows.append(rec)
            f.write(json.dumps(rec) + "\n")
            f.flush()
            if i % 10 == 0 or not rec.get("ok"):
                print(f"{i}/{len(sha)} ok={rec.get('ok')} http={rec.get('http_status')} n={rec.get('n')}")
    orig = {
        "n_query": len(sha),
        "n_ok": sum(1 for r in rows if r.get("ok")),
        "n_missing_on_vt": sum(1 for r in rows if r.get("http_status") == 404),
        "rows": rows,
    }
    ok = [r for r in rows if r.get("ok")]
    rates = [float(r["detection_rate"]) for r in ok]
    ns = [int(r["n"]) for r in ok]
    orig["detection_rate"] = {
        "min": float(min(rates)) if rates else None,
        "max": float(max(rates)) if rates else None,
        "mean": float(sum(rates) / len(rates)) if rates else None,
    }
    orig["n_engines_hits"] = {
        "min": int(min(ns)) if ns else None,
        "max": int(max(ns)) if ns else None,
        "mean": float(sum(ns) / len(ns)) if ns else None,
    }
    (out / "vt_original_reports.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    orig_save = {k: v for k, v in orig.items() if k != "rows"}
    save_json(out / "vt_original_summary.json", orig_save)

    adv = None
    pe_dir = ROOT / "data" / "pe" / "malware"
    if args.upload_pe and pe_dir.is_dir():
        rows = []
        for h in sha:
            hits = list(pe_dir.glob(f"{h}*")) + list(pe_dir.glob(f"{h.lower()}*"))
            if not hits:
                rows.append({"ok": False, "error": "no_local_pe", "sha256": h})
                continue
            up = client.upload_file(hits[0])
            up["parent_sha256"] = h
            rows.append(up)
        adv = {"n_ok": sum(1 for r in rows if r.get("ok")), "rows": rows}
        save_json(out / "vt_upload_mutants.json", rows)

    table6, table7 = table6_7(orig, adv, n_engines_paper=cfg.vt_n_engines)
    save_json(out / "table6_engine_detection.json", table6)
    save_json(out / "table7_evasion.json", table7)
    print(json.dumps({"table6": table6, "table7": table7}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
