from __future__ import annotations

import json
import shutil
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


def sha_list(value) -> list[str]:
    """Hash column from the npz. A NumPy array must not be used with ``or``."""
    if value is None:
        return []
    return [str(item) for item in value]


def assert_lab_scale(cfg: Config, y_train: np.ndarray, y_test: np.ndarray) -> None:
    """Refuse the 25k EMBER stand-in and any other corpus size."""
    n_mal = int((y_train == 1).sum() + (y_test == 1).sum())
    n_ben = int((y_train == 0).sum() + (y_test == 0).sum())
    n_test_mal = int((y_test == 1).sum())
    n_test_ben = int((y_test == 0).sum())
    if (
        n_mal == cfg.n_malware
        and n_ben == cfg.n_benign
        and n_test_mal == cfg.n_test_malware
        and n_test_ben == 0
    ):
        return
    raise RuntimeError(
        f"dataset has {n_mal} malware + {n_ben} benign "
        f"(test {n_test_mal} malware / {n_test_ben} benign); "
        f"this lab expects {cfg.n_malware} malware + {cfg.n_benign} benign, "
        f"test {cfg.n_test_malware} malware / 0 benign. "
        "The paper25k npz is the EMBER 25000+10000 stand-in and must not overwrite "
        "Table 4–5. Rebuild dataset.npz from data/pe/malware and data/pe/benign."
    )


def run(cfg: Config, root: Path, dataset_dir: str | None = None) -> dict:
    rng = np.random.default_rng(cfg.seed)
    out = Path(cfg.out_dir)
    models = Path(cfg.model_dir)
    out.mkdir(parents=True, exist_ok=True)
    models.mkdir(parents=True, exist_ok=True)

    data = load_paper_dataset(root, dataset_dir)
    assert_lab_scale(cfg, data["y_train"], data["y_test"])
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
            "sparse_success_rate": pools["sparse_success_rate"],
            "mean_added": pools["mean_added"],
            "mean_added_all": pools["mean_added_all"],
            "gan_max_added": cfg.gan_max_added,
        },
    )

    env = MalwareEnv(cfg, rf, pools, rng)
    agent = DQNAgent(cfg, cfg.seed + 7)
    vocab_path = root / (dataset_dir or "data/paper25k") / "vocab.json"
    vocab = json.loads(vocab_path.read_text(encoding="utf-8")) if vocab_path.is_file() else None
    mal_dir = root / "data" / "pe" / "malware"
    sha_tr = data.get("sha256_train")
    train_paths = None
    if vocab is not None and sha_tr is not None and len(sha_tr) == len(ytr):
        mal_sha = [str(s) for s, yv in zip(sha_tr, ytr) if int(yv) == 1]
        if len(mal_sha) == len(mal_tr):
            cand = [mal_dir / f"{s}.exe" for s in mal_sha]
            if all(p.is_file() for p in cand):
                train_paths = cand
    work = out / "pe_work"
    print(
        f"DQN train episodes={cfg.episodes} pe_files={train_paths is not None}",
        flush=True,
    )
    if train_paths is not None:
        dqn_hist = agent.train(env, mal_tr, rng, train_paths, work, vocab)
    else:
        dqn_hist = agent.train(env, mal_tr, rng)
    if env.edit_failures:
        print(f"pe edits skipped={env.edit_failures}", flush=True)

    n_eval = min(cfg.eval_n, len(mal_te))
    print(f"mutate eval_n={n_eval}", flush=True)
    orig = mal_te[:n_eval]
    adv = np.zeros_like(orig)
    mutate_log = []
    mut_dir = out / "mutants"
    mut_dir.mkdir(parents=True, exist_ok=True)
    sha_te = sha_list(data.get("sha256_test"))
    n_mut = 0
    for i in range(n_eval):
        src = mal_dir / f"{sha_te[i]}.exe" if vocab is not None and i < len(sha_te) else None
        if src is not None and src.is_file():
            vec, info = agent.mutate(env, orig[i], rng, src, work, vocab)
            if env.pe_path is not None and Path(env.pe_path).is_file():
                shutil.copy2(env.pe_path, mut_dir / f"{sha_te[i]}.mut.exe")
                info["mutant"] = f"{sha_te[i]}.mut.exe"
                n_mut += 1
        else:
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
            "status": "have_mutants" if n_mut else "need_adversarial_pe",
            "n_mutants": n_mut,
            "mutant_dir": str(mut_dir),
            "reason": (
                "Eq. (4) compares VirusTotal on the original hash and the mutant PE. "
                "Mutants are in results/.../mutants."
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
    summary["pe_edits_skipped"] = int(env.edit_failures)
    save_json(out / "cuckoo_status.json", cuckoo)
    save_json(out / "summary.json", summary)
    if env._editor is not None:
        env._editor.close()
    return summary


def _vt_status(cfg: Config, root: Path, data: dict, n_eval: int) -> dict:
    client = VirusTotalClient(rate_sleep=cfg.vt_rate_sleep)
    sha = sha_list(data.get("sha256_test"))[:n_eval]
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
        "cmd": (
            f"python scripts/vt_table67.py --dataset {data.get('source') or 'data/dike2500'} "
            f"--eval-n {n_eval}"
        ),
    }
