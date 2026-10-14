#!/usr/bin/env python3
"""Build a smaller 3523-d set from data/paper25k jsonl. Does not touch the 25k npz."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from if_malevade.data import write_count_subset  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--malware", type=int, default=2500)
    parser.add_argument("--benign", type=int, default=100)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out", default="data/lab2500")
    args = parser.parse_args()
    src = ROOT / "data" / "paper25k"
    meta = write_count_subset(
        src / "malware_raw.jsonl",
        src / "benign_raw.jsonl",
        src / "vocab.json",
        src / "paper_families.json",
        ROOT / args.out,
        n_malware=args.malware,
        n_benign=args.benign,
        seed=args.seed,
    )
    print(json.dumps(meta, indent=2))
    print("wrote", ROOT / args.out / "dataset.npz")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
