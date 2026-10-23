"""Submit one file to the lab Cuckoo 3 API and wait for its post report.

Smoke (benign Windows binary already in the repo):

    python scripts/cuckoo_gate.py --smoke

One file, still inside the guest only:

    python scripts/cuckoo_gate.py --file path\\to\\sample.exe
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from if_malevade.cuckoo_client import (  # noqa: E402
    CuckooClient,
    signature_names,
    signatures_match,
)


def _eval_sha(index: int) -> str:
    import numpy as np

    data = np.load(ROOT / "data" / "lab_dataset" / "dataset.npz", allow_pickle=True)
    column = [str(item) for item in data["sha256_test"]]
    meta_path = ROOT / "data" / "lab_dataset" / "meta.json"
    limit = 50
    if meta_path.is_file():
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if meta.get("eval_n") is not None:
            limit = int(meta["eval_n"])
    chosen = column[:limit]
    if index < 0 or index >= len(chosen):
        raise SystemExit(f"pair-index {index} outside 0..{len(chosen) - 1}")
    return chosen[index]


def _run_pair(client: CuckooClient, args: argparse.Namespace) -> int:
    sha = _eval_sha(args.pair_index)
    orig = ROOT / "data" / "pe" / "malware" / f"{sha}.exe"
    adv = ROOT / "results" / "lab_dataset" / "mutants" / f"{sha}.mut.exe"
    health = client.health()
    print(json.dumps({"health_status": health.get("status"), "pair_index": args.pair_index}), flush=True)
    if health.get("status") != "online":
        print("cuckoo api offline", flush=True)
        return 3
    s0 = client.submit_file(orig, timeout_s=args.timeout)
    s1 = client.submit_file(adv, timeout_s=args.timeout)
    print(
        json.dumps(
            {
                "orig_analysis_id": s0.get("analysis_id"),
                "adv_analysis_id": s1.get("analysis_id"),
                "orig_ok": s0.get("ok"),
                "adv_ok": s1.get("ok"),
                "orig_error": s0.get("error"),
                "adv_error": s1.get("error"),
            }
        ),
        flush=True,
    )
    if not (s0.get("ok") and s1.get("ok")):
        return 4

    def _show(label: str):
        def inner(state: str, view: dict) -> None:
            print(f"{label} state={state} tasks={len(view.get('tasks') or [])}", flush=True)

        return inner

    r0 = client.wait_report(
        str(s0["analysis_id"]), poll=args.poll, max_wait=args.max_wait, on_state=_show("orig")
    )
    r1 = client.wait_report(
        str(s1["analysis_id"]), poll=args.poll, max_wait=args.max_wait, on_state=_show("adv")
    )
    finished = r0.get("state") == "finished" and r1.get("state") == "finished"
    summary = {
        "pair_index": args.pair_index,
        "sha256": sha,
        "orig_analysis_id": s0.get("analysis_id"),
        "adv_analysis_id": s1.get("analysis_id"),
        "orig_state": r0.get("state"),
        "adv_state": r1.get("state"),
        "orig_error": r0.get("error"),
        "adv_error": r1.get("error"),
        "orig_signatures": sorted(signature_names(r0)),
        "adv_signatures": sorted(signature_names(r1)),
        "match": bool(finished and signatures_match(r0, r1, min_recall=1.0)),
        "min_recall": 1.0,
    }
    out = ROOT / "results" / "lab_dataset" / f"cuckoo_pair{args.pair_index}.json"
    out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2), flush=True)
    return 0 if finished else 5


def main() -> int:
    parser = argparse.ArgumentParser(description="One Cuckoo 3 analysis on this lab guest")
    parser.add_argument("--smoke", action="store_true", help="Submit data/cuckoo/smoke/where.exe")
    parser.add_argument("--file", type=Path, help="One PE to submit")
    parser.add_argument(
        "--pair-index",
        type=int,
        default=None,
        help="Eval index: original PE plus results/lab_dataset/mutants/<sha>.mut.exe",
    )
    parser.add_argument("--timeout", type=int, default=120, help="Guest analysis timeout in seconds")
    parser.add_argument("--poll", type=float, default=15.0)
    parser.add_argument("--max-wait", type=float, default=1800.0)
    parser.add_argument(
        "--out",
        type=Path,
        default=ROOT / "results" / "lab_dataset" / "cuckoo_smoke.json",
    )
    args = parser.parse_args()
    client = CuckooClient(timeout=30)
    if args.pair_index is not None:
        return _run_pair(client, args)

    if args.smoke:
        target = ROOT / "data" / "cuckoo" / "smoke" / "where.exe"
    elif args.file:
        target = args.file
    else:
        parser.error("pass --smoke, --file, or --pair-index")
        return 2

    health = client.health()
    print(json.dumps({"health": health}, default=str), flush=True)
    if health.get("status") != "online":
        print("cuckoo api offline", flush=True)
        return 3

    submitted = client.submit_file(target, timeout_s=args.timeout)
    print(json.dumps({"submit": submitted}, default=str), flush=True)
    if not submitted.get("ok"):
        return 4
    analysis_id = str(submitted["analysis_id"])

    def _show(state: str, view: dict) -> None:
        tasks = view.get("tasks") or []
        print(f"state={state} tasks={len(tasks)}", flush=True)

    report = client.wait_report(
        analysis_id, poll=args.poll, max_wait=args.max_wait, on_state=_show
    )
    summary = {
        "file": target.name,
        "analysis_id": analysis_id,
        "state": report.get("state"),
        "ok": bool(report.get("ok")),
        "error": report.get("error"),
        "signatures": sorted(signature_names(report)),
        "tasks": [
            {"id": t.get("id"), "state": t.get("state")}
            for t in (report.get("tasks") or [])
            if isinstance(t, dict)
        ],
        "errors": report.get("errors"),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2), flush=True)
    return 0 if summary["ok"] else 5


if __name__ == "__main__":
    raise SystemExit(main())
