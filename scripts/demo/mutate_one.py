#!/usr/bin/env python3
"""Mutate one new PE into demo_one. Does not rewrite results/lab_dataset."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from if_malevade.demo_policy import mutate_pe, policy_path  # noqa: E402


def main() -> int:
    if not policy_path(ROOT).is_file():
        print("Chua co models/lab_dataset/demo_policy.npz", flush=True)
        print("Chay truoc: python -u scripts\\demo\\fit_demo_policy.py", flush=True)
        return 1
    if len(sys.argv) > 1:
        raw = " ".join(sys.argv[1:]).strip().strip('"')
    else:
        raw = input("Duong dan file moi: ").strip().strip('"')
    src = Path(raw)
    if not src.is_file():
        print(f"Khong thay file: {src}", flush=True)
        return 1
    dest = ROOT / "demo_one" / f"{src.stem}.mut.exe"
    info = mutate_pe(ROOT, src, dest)
    print(f"turns {info['turn']}", flush=True)
    print(f"evaded {info['evaded']}", flush=True)
    print("actions " + ", ".join(info["actions_named"]), flush=True)
    print(f"output {dest}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
