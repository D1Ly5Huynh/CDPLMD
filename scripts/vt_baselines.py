#!/usr/bin/env python3
"""VirusTotal columns for the lab MalFox and MAB mutants.

Original reports stay in results/<dataset>/vt_original_reports.jsonl.
IF-MalEvade mutant reports stay in vt_upload_mutants.jsonl.
This script only POSTs baselines/<method>/{sha}.mut.exe to
https://www.virustotal.com/api/v3 and appends vt_upload_<method>.jsonl.

  python scripts/vt_baselines.py --dataset data/lab_dataset
  python scripts/vt_baselines.py --dataset data/lab_dataset --rebuild
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
from if_malevade.metrics import save_json  # noqa: E402
from if_malevade.vt_client import VirusTotalClient, table6_7, vt_job_paths  # noqa: E402

METHODS = ("mab", "malfox")


def brief_vt_error(rec: dict) -> str:
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


def _mutant(out: Path, method: str, sha: str) -> Path | None:
    path = out / "baselines" / method / f"{sha}.mut.exe"
    return path if path.is_file() else None


def _score(orig_rows: list[dict], adv_rows: list[dict], n_engines: int) -> tuple[dict, dict]:
    rates = [float(r["detection_rate"]) for r in orig_rows if r.get("detection_rate") is not None]
    orig = {
        "n_ok": len(orig_rows),
        "detection_rate": {
            "min": float(min(rates)) if rates else None,
            "max": float(max(rates)) if rates else None,
            "mean": float(sum(rates) / len(rates)) if rates else None,
        },
        "rows": orig_rows,
    }
    adv = {"n_ok": len(adv_rows), "rows": adv_rows} if adv_rows else None
    return table6_7(orig, adv, n_engines_paper=n_engines)


def _vt_public(table6: dict, table7: dict, n_target: int, jsonl: Path) -> dict:
    n_pairs = int(table7.get("n_pairs") or 0)
    status = "done" if table7.get("status") == "done" and n_pairs >= n_target and n_target > 0 else "partial"
    if n_pairs == 0:
        status = "chua_chay"
    return {
        "status": status,
        "n_target": n_target,
        "n_pairs": n_pairs,
        "detection_rate": table6.get("detection_rate_adversarial"),
        "evasion_rate": table7.get("evasion_rate"),
        "n_engines_observed": table7.get("n_engines_observed"),
        "jsonl": jsonl.name,
    }


def _merge_baselines(out: Path, method: str, public: dict, table6: dict, table7: dict) -> None:
    path = out / "baselines.json"
    doc = {}
    if path.is_file():
        doc = json.loads(path.read_text(encoding="utf-8"))
    row = doc.get(method) if isinstance(doc.get(method), dict) else {}
    row["vt"] = public
    doc[method] = row
    save_json(path, doc)
    save_json(out / "baselines" / f"vt_{method}_table.json", {"table6": table6, "table7": table7})


def _upload_one(client: VirusTotalClient, path: Path) -> dict:
    last_error = "read_failed"
    for _attempt in range(3):
        try:
            rec = client.finish_upload(client.upload_file(path), timeout_s=900)
        except OSError as exc:
            last_error = f"read_failed errno={getattr(exc, 'errno', '')}"
            print(f"read retry {path.name} {last_error}", flush=True)
            time.sleep(2)
            continue
        if not rec.get("ok") and _retryable_upload(rec):
            print(f"retry after {brief_vt_error(rec)}", flush=True)
            time.sleep(30)
            try:
                rec = client.finish_upload(client.upload_file(path), timeout_s=900)
            except OSError as exc:
                last_error = f"read_failed errno={getattr(exc, 'errno', '')}"
                time.sleep(2)
                continue
        if rec.get("error"):
            rec["error"] = brief_vt_error(rec)
        return rec
    return {"ok": False, "error": last_error, "path": str(path)}


def run_method(
    client: VirusTotalClient | None,
    out: Path,
    method: str,
    orig_rows: list[dict],
    n_engines: int,
    rebuild_only: bool,
) -> int:
    sha_list = [str(r["sha256"]) for r in orig_rows if r.get("sha256")]
    jsonl = out / f"vt_upload_{method}.jsonl"
    if jsonl.resolve() == (out / "vt_upload_mutants.jsonl").resolve():
        print("refusing to write the IF-MalEvade mutant jsonl")
        return 2
    done = {str(r["parent_sha256"]): r for r in _latest_ok(jsonl, "parent_sha256", require_n=True)}
    rows: list[dict] = []
    if not rebuild_only:
        assert client is not None
        jsonl.parent.mkdir(parents=True, exist_ok=True)
        with jsonl.open("a", encoding="utf-8") as handle:
            for i, sha in enumerate(sha_list, 1):
                prev = done.get(sha)
                if prev is not None:
                    rows.append(prev)
                    print(f"{method} {i}/{len(sha_list)} resume n={prev.get('n')}", flush=True)
                    continue
                mut = _mutant(out, method, sha)
                if mut is None:
                    rec = {"ok": False, "error": "no_mutant", "sha256": sha, "parent_sha256": sha}
                else:
                    print(f"{method} {i}/{len(sha_list)} upload {mut.name}", flush=True)
                    rec = _upload_one(client, mut)
                    rec["parent_sha256"] = sha
                rows.append(rec)
                if rec.get("http_status") in (401, 403):
                    handle.write(json.dumps(rec) + "\n")
                    handle.flush()
                    print(f"{method} stop http={rec.get('http_status')}", flush=True)
                    return 2
                if rec.get("ok") and rec.get("n") is not None:
                    done[sha] = rec
                handle.write(json.dumps(rec) + "\n")
                handle.flush()
                print(
                    f"{method} {i}/{len(sha_list)} ok={rec.get('ok')} n={rec.get('n')} "
                    f"http={rec.get('http_status')} err={brief_vt_error(rec) if rec.get('error') else ''}",
                    flush=True,
                )
                adv_rows = list(done.values())
                table6, table7 = _score(orig_rows, adv_rows, n_engines)
                _merge_baselines(out, method, _vt_public(table6, table7, len(sha_list), jsonl), table6, table7)
    else:
        rows = list(done.values())

    adv_rows = [r for r in rows if r.get("ok") and r.get("n") is not None]
    table6, table7 = _score(orig_rows, adv_rows, n_engines)
    public = _vt_public(table6, table7, len(sha_list), jsonl)
    _merge_baselines(out, method, public, table6, table7)
    det = (public.get("detection_rate") or {}).get("mean")
    ev = (public.get("evasion_rate") or {}).get("mean")
    print(
        f"{method} status={public['status']} pairs={public['n_pairs']}/{public['n_target']} "
        f"detection_mean={det} evasion_mean={ev}",
        flush=True,
    )
    return 0 if public["status"] == "done" else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default="data/lab_dataset")
    parser.add_argument("--method", choices=("mab", "malfox", "both"), default="both")
    parser.add_argument("--rebuild", action="store_true")
    args = parser.parse_args()
    cfg = Config()
    try:
        _data_dir, out = vt_job_paths(ROOT, args.dataset)
    except ValueError as exc:
        print(exc)
        return 2
    orig_rows = _latest_ok(out / "vt_original_reports.jsonl", "sha256")
    if not orig_rows:
        print(f"missing ok rows in {out / 'vt_original_reports.jsonl'}")
        return 2
    client = None
    if not args.rebuild:
        client = VirusTotalClient(rate_sleep=cfg.vt_rate_sleep)
        if not client.has_key():
            print("missing VT_API_KEY (or data/vt.api)")
            return 2
    methods = METHODS if args.method == "both" else (args.method,)
    code = 0
    for method in methods:
        code = max(code, run_method(client, out, method, orig_rows, cfg.vt_n_engines, args.rebuild))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
