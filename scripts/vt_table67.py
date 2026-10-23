#!/usr/bin/env python3
"""VirusTotal Table 6–7 (IF-MalEvade eqs. 3–4).

Originals: GET /files/{sha256} — no bytes uploaded.
Mutants: POST only results/<dataset>/mutants/{sha}.mut.exe when --upload-pe is set.

  python scripts/vt_table67.py --dataset data/lab_dataset --eval-n 50
  python scripts/vt_table67.py --eval-n 5   # smoke, still data/lab_dataset

``--eval-n 500`` is the paper size. On data/lab_dataset that flag is larger than
the test split, so the script uses meta.json eval_n (50) and writes under
results/lab_dataset. It does not open data/paper25k or results/vt_original_reports.jsonl.
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
from if_malevade.vt_client import (  # noqa: E402
    VirusTotalClient,
    mutant_file,
    select_eval_hashes,
    table6_7,
    vt_job_paths,
)


def brief_vt_error(rec: dict) -> str:
    """One line for the terminal. A proxy block page is not a VirusTotal JSON error."""
    err = str(rec.get("error") or "")
    if "High Security Alert" in err or "not permitted to transfer the file" in err:
        return "local_filter_blocked"
    if "getaddrinfo failed" in err:
        return "dns_failed"
    if err.startswith("<!") or "<html" in err[:240].lower():
        return f"http_{rec.get('http_status')}_html"
    return err.replace("\n", " ")[:180]


def _retryable_upload(rec: dict) -> bool:
    err = brief_vt_error(rec)
    return err in {"local_filter_blocked", "dns_failed", "analysis_timeout"} or err.startswith("http_")


def _latest_ok(path: Path, key: str, require_n: bool = False) -> list[dict]:
    """Last successful jsonl record for each hash. A later error does not erase it."""
    found: dict[str, dict] = {}
    if not path.is_file():
        return []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        ident = str(rec.get(key) or "")
        if not ident or not rec.get("ok"):
            continue
        if require_n and rec.get("n") is None:
            continue
        found[ident] = rec
    return list(found.values())


def _rebuild(cfg: Config, dataset: str) -> int:
    try:
        _data_dir, out = vt_job_paths(ROOT, dataset)
    except ValueError as exc:
        print(exc)
        return 2
    orig_rows = _latest_ok(out / "vt_original_reports.jsonl", "sha256")
    adv_rows = _latest_ok(out / "vt_upload_mutants.jsonl", "parent_sha256", require_n=True)
    if not orig_rows:
        print(f"missing ok rows in {out / 'vt_original_reports.jsonl'}")
        return 2
    rates = [float(r["detection_rate"]) for r in orig_rows if r.get("detection_rate") is not None]
    ns = [int(r["n"]) for r in orig_rows if r.get("n") is not None]
    orig = {
        "n_query": len(orig_rows),
        "n_ok": len(orig_rows),
        "n_missing_on_vt": 0,
        "detection_rate": {
            "min": float(min(rates)) if rates else None,
            "max": float(max(rates)) if rates else None,
            "mean": float(sum(rates) / len(rates)) if rates else None,
        },
        "n_engines_hits": {
            "min": int(min(ns)) if ns else None,
            "max": int(max(ns)) if ns else None,
            "mean": float(sum(ns) / len(ns)) if ns else None,
        },
        "rows": orig_rows,
    }
    adv = {"n_ok": len(adv_rows), "rows": adv_rows} if adv_rows else None
    table6, table7 = table6_7(orig, adv, n_engines_paper=cfg.vt_n_engines)
    table6["status"] = "done"
    table6["n_eval_hashes"] = len(orig_rows)
    if table7.get("status") == "done":
        table7["mutant_dir"] = str(out / "mutants")
    save_json(out / "table6_engine_detection.json", table6)
    save_json(out / "table7_evasion.json", table7)
    summary_path = out / "summary.json"
    if summary_path.is_file():
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        summary["table6"] = table6
        summary["table7"] = table7
        save_json(summary_path, summary)
    slim6 = {k: v for k, v in table6.items()}
    print(json.dumps({"n_original": len(orig_rows), "n_mutant": len(adv_rows), "table6": slim6, "table7": table7}, indent=2))
    return 0


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--dataset", default="data/lab_dataset")
    p.add_argument(
        "--eval-n",
        type=int,
        default=None,
        help="hash count; 500 on this lab split uses meta.json eval_n",
    )
    p.add_argument(
        "--upload-pe",
        action="store_true",
        help="upload results/<dataset>/mutants/{sha}.mut.exe",
    )
    p.add_argument(
        "--rebuild",
        action="store_true",
        help="recompute Table 6–7 from saved jsonl; no VirusTotal calls",
    )
    args = p.parse_args()
    cfg = Config()
    if args.rebuild:
        return _rebuild(cfg, args.dataset)
    client = VirusTotalClient(rate_sleep=cfg.vt_rate_sleep)
    if not client.has_key():
        print("missing VT_API_KEY (or data/vt.api)")
        return 2
    try:
        data_dir, out = vt_job_paths(ROOT, args.dataset)
    except ValueError as exc:
        print(exc)
        return 2
    data = load_paper_dataset(ROOT, args.dataset)
    sha_arr = data.get("sha256_test")
    sha_all = [str(x) for x in (sha_arr if sha_arr is not None else []) if str(x)]
    meta_eval = None
    meta_path = data_dir / "meta.json"
    if meta_path.is_file():
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if meta.get("eval_n") is not None:
            meta_eval = int(meta["eval_n"])
    sha, note = select_eval_hashes(sha_all, args.eval_n, meta_eval)
    if not sha:
        print(f"{data_dir / 'dataset.npz'} has no sha256_test")
        return 2
    print(f"dataset={args.dataset} {note} out={out}", flush=True)
    out.mkdir(parents=True, exist_ok=True)
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
    if args.upload_pe:
        rows = []
        upload_jsonl = out / "vt_upload_mutants.jsonl"
        uploaded: dict[str, dict] = {}
        if upload_jsonl.is_file():
            for line in upload_jsonl.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                prev = json.loads(line)
                parent = str(prev.get("parent_sha256") or "")
                if parent and prev.get("ok") and prev.get("n") is not None:
                    uploaded[parent] = prev
            print(f"resume uploads {len(uploaded)} ok in {upload_jsonl}", flush=True)
        with upload_jsonl.open("a", encoding="utf-8") as upload_f:
            for i, h in enumerate(sha, 1):
                prev = uploaded.get(h)
                if prev is not None:
                    rows.append(prev)
                    print(f"upload {i}/{len(sha)} resume n={prev.get('n')}", flush=True)
                    continue
                mut = mutant_file(out, h)
                if mut is None:
                    rec = {"ok": False, "error": "no_mutant", "sha256": h, "parent_sha256": h}
                else:
                    print(f"upload {i}/{len(sha)} {mut.name}", flush=True)
                    rec = client.finish_upload(client.upload_file(mut), timeout_s=900)
                    if not rec.get("ok") and _retryable_upload(rec):
                        print(
                            f"upload {i}/{len(sha)} retry after {brief_vt_error(rec)}",
                            flush=True,
                        )
                        time.sleep(30)
                        rec = client.finish_upload(client.upload_file(mut), timeout_s=900)
                    rec["parent_sha256"] = h
                    if rec.get("error"):
                        rec["error"] = brief_vt_error(rec)
                rows.append(rec)
                upload_f.write(json.dumps(rec) + "\n")
                upload_f.flush()
                print(
                    f"upload {i}/{len(sha)} ok={rec.get('ok')} n={rec.get('n')} "
                    f"http={rec.get('http_status')} err={brief_vt_error(rec) if rec.get('error') else ''}",
                    flush=True,
                )
        adv = {"n_ok": sum(1 for r in rows if r.get("ok") and r.get("n") is not None), "rows": rows}
        save_json(out / "vt_upload_mutants.json", rows)

    table6, table7 = table6_7(orig, adv, n_engines_paper=cfg.vt_n_engines)
    save_json(out / "table6_engine_detection.json", table6)
    save_json(out / "table7_evasion.json", table7)
    print(json.dumps({"table6": table6, "table7": table7}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
