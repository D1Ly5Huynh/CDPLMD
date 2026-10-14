#!/usr/bin/env python3
"""Build data/dike2500 from the Dike PE folders. Does not train."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from if_malevade.data import write_pe_dataset  # noqa: E402


def main() -> int:
    meta = write_pe_dataset(
        ROOT / "data" / "pe" / "malware",
        ROOT / "data" / "pe" / "benign",
        ROOT / "data" / "dike2500",
        n_test_malware=100,
        seed=42,
    )
    print(json.dumps(meta, indent=2))
    print("wrote", ROOT / "data" / "dike2500" / "dataset.npz")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
