#!/usr/bin/env python3
"""MalFox and MAB-Malware baselines on the 50-sample lab eval set.

Black box is the saved Gradient Boosting detector. Edits are the seven
Table 3 actions. Mutants go to results/<name>/baselines/{mab,malfox}/.
This command does not call VirusTotal.

  python scripts/run_baselines.py --dataset data/dike2500
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import joblib
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from if_malevade.baselines import (  # noqa: E402
    benign_pools,
    run_mab_thompson,
    run_malfox,
    train_malfox_policy,
)
from if_malevade.config import Config  # noqa: E402
from if_malevade.data import apply_cfg_dims, load_paper_dataset, split_malware  # noqa: E402
from if_malevade.detectors import detection_rate  # noqa: E402
from if_malevade.env import MalwareEnv  # noqa: E402
from if_malevade.metrics import save_json  # noqa: E402
from if_malevade.pe_mutate import EditSession  # noqa: E402
from if_malevade.pipeline import sha_list  # noqa: E402


def _public(row: dict) -> dict:
    skip = {"adv", "alpha", "beta"}
    return {key: value for key, value in row.items() if key not in skip}


def _adr(detectors, adv, threshold: float) -> dict:
    return {name: detection_rate(clf, adv, threshold) for name, clf in detectors.items()}


def _load_run(dataset: str):
    cfg = Config()
    data = load_paper_dataset(ROOT, dataset)
    cfg = apply_cfg_dims(cfg, data)
    Xtr, ytr = data["X_train"], data["y_train"]
    Xte, yte = data["X_test"], data["y_test"]
    mal_tr, _ben = split_malware(Xtr, ytr)
    mal_te, _ = split_malware(Xte, yte)
    n_eval = min(cfg.eval_n, len(mal_te))
    samples = mal_te[:n_eval]
    sha = sha_list(data.get("sha256_test"))[:n_eval]
    mal_dir = ROOT / "data" / "pe" / "malware"
    paths = [mal_dir / f"{item}.exe" for item in sha]
    missing = [str(path) for path in paths if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"missing {len(missing)} eval PE, first {missing[0]}")
    vocab = json.loads((ROOT / dataset / "vocab.json").read_text(encoding="utf-8"))
    name = dataset.split("/")[-1]
    detectors = joblib.load(ROOT / "models" / name / "detectors.joblib")
    return cfg, data, mal_tr, samples, sha, paths, vocab, detectors, name


def rebuild_missing_mab(dataset: str) -> int:
    """Rewrite MAB mutants that are no longer on disk. Leave surviving files in place."""
    cfg, _data, _mal_tr, samples, sha, paths, vocab, detectors, name = _load_run(dataset)
    out = ROOT / "results" / name / "baselines"
    mab_dir = out / "mab"
    hold = out / "mab_hold"
    mab_dir.mkdir(parents=True, exist_ok=True)
    if hold.is_dir():
        for src in hold.glob("*.mut.exe"):
            dest = mab_dir / src.name
            if not dest.is_file():
                shutil.move(str(src), str(dest))
    missing_idx = [i for i, item in enumerate(sha) if not (mab_dir / f"{item}.mut.exe").is_file()]
    print(f"mab on disk {len(sha) - len(missing_idx)}/{len(sha)} missing {len(missing_idx)}", flush=True)
    written = 0
    if missing_idx:
        blackbox = detectors["GradientBoosting"]
        pools = benign_pools(_data["X_train"], _data["y_train"], cfg)
        rng = np.random.default_rng(cfg.seed + 11)
        env = MalwareEnv(cfg, blackbox, pools, rng)
        env._editor = EditSession(timeout_s=25)
        row = run_mab_thompson(
            env,
            samples[missing_idx],
            [paths[i] for i in missing_idx],
            mab_dir,
            out / "mab_work",
            vocab,
            rng,
        )
        written = int(row["n_written"])
    still_missing = [sha[i] for i in missing_idx if not (mab_dir / f"{sha[i]}.mut.exe").is_file()]
    doc_path = ROOT / "results" / name / "baselines.json"
    if doc_path.is_file():
        doc = json.loads(doc_path.read_text(encoding="utf-8"))
        mab = doc.get("mab") if isinstance(doc.get("mab"), dict) else {}
        note = str(mab.get("note") or "")
        extra = (
            f"Sinh lại {written} file MAB sau khi Defender xóa. "
            "File còn trên đĩa được giữ nguyên."
        )
        if extra not in note:
            mab["note"] = (note + " " + extra).strip()
        mab["regenerated"] = {"n_missing": len(missing_idx), "n_written": written, "n_still_missing": len(still_missing)}
        doc["mab"] = mab
        save_json(doc_path, doc)
    print(f"mab written {written} still_missing {len(still_missing)}", flush=True)
    return 0 if not still_missing else 1


def main() -> int:
    dataset = "data/dike2500"
    args = sys.argv[1:]
    if "--dataset" in args:
        dataset = args[args.index("--dataset") + 1]
    if "--rebuild-missing" in args:
        return rebuild_missing_mab(dataset)
    try:
        cfg, data, mal_tr, samples, sha, paths, vocab, detectors, _name = _load_run(dataset)
    except FileNotFoundError as exc:
        print(exc)
        return 2
    Xtr, ytr = data["X_train"], data["y_train"]
    n_eval = len(sha)
    blackbox = detectors["GradientBoosting"]
    pools = benign_pools(Xtr, ytr, cfg)
    rng = np.random.default_rng(cfg.seed + 11)
    out = ROOT / "results" / dataset.split("/")[-1] / "baselines"
    print(
        f"baselines n={n_eval} features={cfg.n_features} "
        f"import_pool={len(pools['imports'])} section_pool={len(pools['sections'])}",
        flush=True,
    )
    print("train malfox policy on feature vectors", flush=True)
    weight = train_malfox_policy(blackbox, mal_tr, pools, cfg, rng)
    mab_env = MalwareEnv(cfg, blackbox, pools, rng)
    mab_env._editor = EditSession(timeout_s=25)
    fox_env = MalwareEnv(cfg, blackbox, pools, np.random.default_rng(cfg.seed + 12))
    fox_env._editor = EditSession(timeout_s=25)
    mab = run_mab_thompson(
        mab_env, samples, paths, out / "mab", out / "mab_work", vocab, rng
    )
    fox = run_malfox(
        fox_env, samples, paths, out / "malfox", out / "malfox_work", vocab, weight
    )
    mab_pub = _public(mab)
    fox_pub = _public(fox)
    mab_pub["status"] = "done"
    fox_pub["status"] = "done"
    mab_pub["adr"] = _adr(detectors, mab["adv"], cfg.threshold)
    fox_pub["adr"] = _adr(detectors, fox["adv"], cfg.threshold)
    mab_pub["blackbox"] = "GradientBoosting"
    fox_pub["blackbox"] = "GradientBoosting"
    mab_pub["note"] = (
        "Thompson sampling trên 7 action Table 3. "
        "Không gồm xóa chữ ký, phá checksum, hay code randomization của Song et al."
    )
    fox_pub["note"] = (
        "Đường tối đa 3 action Table 3 từ policy học trên vector. "
        "Không gồm Obfusmal, Stealmal, Hollowmal của Zhong et al."
    )
    body = {"mab": mab_pub, "malfox": fox_pub}
    save_json(out / "summary.json", body)
    save_json(ROOT / "results" / dataset.split("/")[-1] / "baselines.json", body)
    np.save(out / "mab_adv.npy", mab["adv"])
    np.save(out / "malfox_adv.npy", fox["adv"])
    print(json.dumps(body, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
