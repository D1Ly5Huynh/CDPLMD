from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from .config import Config
from .cuckoo_client import CuckooClient
from .data import apply_cfg_dims, load_paper_dataset, split_malware
from .detectors import auc_of, build_detectors, detection_rate, fit_detectors
from .dqn import DQNAgent
from .env import MalwareEnv
from .malgan import MalGAN
from .metrics import odr_adr, save_json
from .vt_client import VirusTotalClient


def run(cfg: Config, root: Path) -> dict:
    rng = np.random.default_rng(cfg.seed)
    out = Path(cfg.out_dir)
    models = Path(cfg.model_dir)
    out.mkdir(parents=True, exist_ok=True)
    models.mkdir(parents=True, exist_ok=True)

    data = load_paper_dataset(root)
    cfg = apply_cfg_dims(cfg, data)
    source = data["source"]

    Xtr, ytr = data["X_train"], data["y_train"]
    Xte, yte = data["X_test"], data["y_test"]
    mal_tr, ben_tr = split_malware(Xtr, ytr)
    mal_te, _ = split_malware(Xte, yte)
    if len(mal_te) < cfg.eval_n:
        raise RuntimeError(
            f"test malware {len(mal_te)} < eval_n {cfg.eval_n} (paper eval 500 of 1000)"
        )

    print(
        f"load source={source} Xtr={Xtr.shape} Xte={Xte.shape} "
        f"mal_tr={len(mal_tr)} mal_te={len(mal_te)}",
        flush=True,
    )
    det_path = models / "detectors.joblib"
    if det_path.exists():
        print(f"load detectors {det_path}", flush=True)
        detectors = joblib.load(det_path)
    else:
        print("fit 4 detectors...", flush=True)
        detectors = fit_detectors(build_detectors(cfg), Xtr, ytr)
        joblib.dump(detectors, det_path)
        print("detectors saved", flush=True)
    rf = detectors["RandomForest"]

    gan = MalGAN(cfg, cfg.seed)
    print(f"MalGAN train epochs={cfg.gan_epochs}", flush=True)
    gan_hist = gan.train(rf, Xtr, ytr, rng)
    print("MalGAN influential pools...", flush=True)
    pools = gan.influential_pools(mal_tr, ben_tr, rf, rng, cfg)
    save_json(
        out / "influential_features.json",
        {
            "n_imports_pool": len(pools["imports"]),
            "n_sections_pool": len(pools["sections"]),
            "success_rate": pools["success_rate"],
            "mean_added": pools["mean_added"],
        },
    )

    env = MalwareEnv(cfg, rf, pools, rng)
    agent = DQNAgent(cfg, cfg.seed + 7)
    print(f"DQN train episodes={cfg.episodes}", flush=True)
    dqn_hist = agent.train(env, mal_tr, rng)

    n_eval = min(cfg.eval_n, len(mal_te))
    print(f"mutate eval_n={n_eval}", flush=True)
    orig = mal_te[:n_eval]
    adv = np.zeros_like(orig)
    mutate_log = []
    for i in range(n_eval):
        vec, info = agent.mutate(env, orig[i], rng)
        adv[i] = vec
        mutate_log.append(info)

    table4 = {}
    for name, clf in detectors.items():
        row = odr_adr(clf, orig, adv, cfg.threshold)
        row["AUC"] = auc_of(clf, Xtr, ytr)
        table4[name] = row

    n_mix = max(1, int(cfg.retrain_frac * len(adv)))
    X_re = np.vstack([Xtr, adv[:n_mix]])
    y_re = np.concatenate([ytr, np.ones(n_mix, dtype=np.int32)])
    retrained = fit_detectors(build_detectors(cfg), X_re, y_re)
    table5 = {}
    for name in detectors:
        table5[name] = {
            "ADR_before": table4[name]["ADR"],
            "ADR_after": detection_rate(retrained[name], adv, cfg.threshold),
        }

    pd.DataFrame(table4).T.to_csv(out / "table4_ml_detectors.csv")
    pd.DataFrame(table5).T.to_csv(out / "table5_adversarial_retrain.csv")

    summary = {
        "preset": cfg.name,
        "source": source,
        "n_features": cfg.n_features,
        "n_train": int(len(ytr)),
        "n_test": int(len(yte)),
        "n_eval": n_eval,
        "gan_last_evade_batch": gan_hist["evade_batch"][-1] if gan_hist["evade_batch"] else None,
        "dqn_evade_last20": float(np.mean(dqn_hist["evade"][-20:])),
        "mutate_evade": float(np.mean([m["evaded"] for m in mutate_log])),
        "mean_turns": float(np.mean([m["turn"] for m in mutate_log])),
        "table4": table4,
        "table5": table5,
        "table6": _vt_status(cfg, root, data, n_eval),
        "table7": {
            "status": "need_adversarial_pe",
            "reason": (
                "Eq. (4) needs orig vs mutated PE on VirusTotal. "
                "Hash lookup of originals: scripts/vt_table67.py. "
                "Upload mutants when PE files exist under data/pe/malware/."
            ),
        },
        "config": cfg.to_dict(),
    }
    save_json(out / "summary.json", summary)
    (out / "gan_history.json").write_text(json.dumps(gan_hist), encoding="utf-8")
    save_json(out / "dqn_history.json", {k: v for k, v in dqn_hist.items()})
    np.save(out / "adv_vectors.npy", adv)
    np.save(out / "orig_vectors.npy", orig)

    cuckoo = {"status": "disabled"}
    if cfg.cuckoo_enabled:
        client = CuckooClient(base_url=cfg.cuckoo_url, timeout=cfg.cuckoo_timeout)
        cuckoo = client.health()
        cuckoo["note"] = (
            "Paper §IV: keep mutant iff Cuckoo signatures match the parent."
        )
    summary["cuckoo"] = cuckoo
    save_json(out / "cuckoo_status.json", cuckoo)
    save_json(out / "summary.json", summary)
    return summary


def _vt_status(cfg: Config, root: Path, data: dict, n_eval: int) -> dict:
    client = VirusTotalClient(rate_sleep=cfg.vt_rate_sleep)
    sha_arr = data.get("sha256_test")
    sha = [str(x) for x in (sha_arr if sha_arr is not None else [])[:n_eval] if str(x)]
    pe_dir = root / "data" / "pe" / "malware"
    n_pe = len(list(pe_dir.glob("*"))) if pe_dir.is_dir() else 0
    if not cfg.vt_enabled:
        return {"status": "disabled"}
    if not client.has_key():
        return {
            "status": "missing_api_key",
            "n_eval_hashes": len(sha),
            "n_local_pe": n_pe,
            "reason": (
                "Set VT_API_KEY or write data/vt.api. "
                "Originals: hash lookup (no upload). Mutants: need PE files then upload."
            ),
        }
    return {
        "status": "ready_lookup",
        "n_eval_hashes": len(sha),
        "n_local_pe": n_pe,
        "n_engines_paper": cfg.vt_n_engines,
        "cmd": "python scripts/vt_table67.py --eval-n 500",
    }
