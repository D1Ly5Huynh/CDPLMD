#!/usr/bin/env python3
"""Run the IF-MalEvade paper pipeline (Arif et al., IEEE Access 2023).

  python run_experiment.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from if_malevade.config import Config  # noqa: E402
from if_malevade.pipeline import run  # noqa: E402


def main() -> int:
    cfg = Config().resolve(ROOT)
    print(
        f"paper features={cfg.n_features} gan_epochs={cfg.gan_epochs} "
        f"episodes={cfg.episodes} eval_n={cfg.eval_n} max_turn={cfg.max_turn}"
    )
    summary = run(cfg, ROOT)
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
