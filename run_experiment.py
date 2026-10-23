#!/usr/bin/env python3
"""Run the IF-MalEvade paper pipeline (Arif et al., IEEE Access 2023).

  python run_experiment.py
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from if_malevade.config import Config  # noqa: E402
from if_malevade.pipeline import run  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="IF-MalEvade feature-space run")
    parser.add_argument(
        "--dataset",
        default=None,
        help="Dataset directory under CDPLMD, for example data/lab_dataset",
    )
    args = parser.parse_args()
    cfg = Config()
    if args.dataset:
        meta_path = ROOT / args.dataset / "meta.json"
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        cfg.name = Path(args.dataset).name
        cfg.n_malware = int(meta["n_malware"])
        cfg.n_benign = int(meta["n_benign"])
        cfg.n_test_malware = int(meta["n_test_malware"])
        cfg.eval_n = int(meta.get("eval_n") or max(1, cfg.n_test_malware // 2))
        cfg.out_dir = f"results/{cfg.name}"
        cfg.model_dir = f"models/{cfg.name}"
    cfg.resolve(ROOT)
    print(
        f"paper features={cfg.n_features} gan_epochs={cfg.gan_epochs} "
        f"episodes={cfg.episodes} eval_n={cfg.eval_n} max_turn={cfg.max_turn} "
        f"malware={cfg.n_malware} benign={cfg.n_benign}"
    )
    summary = run(cfg, ROOT, dataset_dir=args.dataset)
    keys = (
        "preset",
        "source",
        "n_features",
        "n_eval",
        "mutate_evade",
        "table4",
        "table5",
        "table6",
        "table7",
    )
    print(json.dumps({k: summary[k] for k in keys}, indent=2, default=str))
    print(f"wrote {cfg.out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
