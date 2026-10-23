#!/usr/bin/env python3
"""Fit the demo DQN policy. Does not rewrite results/lab_dataset."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from if_malevade.demo_policy import fit_and_save  # noqa: E402

if __name__ == "__main__":
    path = fit_and_save(ROOT)
    print(f"saved {path}", flush=True)
