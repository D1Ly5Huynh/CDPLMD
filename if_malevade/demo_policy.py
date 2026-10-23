"""Train and reuse one DQN policy for a single new PE. Does not execute the file."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import joblib
import numpy as np

from .config import Config
from .data import load_paper_dataset, split_malware, vectorize_pe
from .detectors import malware_score
from .dqn import DQNAgent
from .env import ACTIONS, MalwareEnv
from .malgan import MalGAN

POLICY_NAME = "demo_policy.npz"


def policy_path(root: Path) -> Path:
    return root / "models" / "lab_dataset" / POLICY_NAME


def _cfg(data: dict) -> Config:
    cfg = Config()
    cfg.name = "lab_dataset"
    cfg.n_imports = int(data["n_imports"])
    cfg.n_sections = int(data["n_sections"])
    return cfg


def fit_and_save(root: Path) -> Path:
    """Fit MalGAN pools and DQN on feature vectors. Leave results/ untouched."""
    root = Path(root)
    data = load_paper_dataset(root, "data/lab_dataset")
    cfg = _cfg(data)
    rng = np.random.default_rng(cfg.seed)
    Xtr, ytr = data["X_train"], data["y_train"]
    mal_tr, ben_tr = split_malware(Xtr, ytr)
    detectors = joblib.load(root / "models" / "lab_dataset" / "detectors.joblib")
    blackbox = detectors["RandomForest"]
    gan = MalGAN(cfg, cfg.seed)
    gan.train(blackbox, Xtr, ytr, rng)
    pools = gan.influential_pools(mal_tr, ben_tr, blackbox, rng, cfg)
    env = MalwareEnv(cfg, blackbox, pools, rng)
    agent = DQNAgent(cfg, cfg.seed + 7)
    agent.train(env, mal_tr, rng)
    dest = policy_path(root)
    dest.parent.mkdir(parents=True, exist_ok=True)
    snap = agent.q.snapshot()
    np.savez(
        dest,
        sizes=np.array(snap["sizes"], dtype=np.int32),
        W0=snap["W"][0],
        W1=snap["W"][1],
        W2=snap["W"][2],
        b0=snap["b"][0],
        b1=snap["b"][1],
        b2=snap["b"][2],
        imports=np.array(pools["imports"], dtype=np.int32),
        sections=np.array(pools["sections"], dtype=np.int32),
    )
    return dest


def load_agent(root: Path) -> tuple[Config, DQNAgent, dict]:
    data = load_paper_dataset(root, "data/lab_dataset")
    cfg = _cfg(data)
    snap_file = np.load(policy_path(root))
    agent = DQNAgent(cfg, cfg.seed + 7)
    agent.q.load_snapshot(
        {
            "sizes": [int(v) for v in snap_file["sizes"]],
            "hidden_act": "relu",
            "out_act": "identity",
            "leaky": cfg.leaky,
            "W": [snap_file["W0"], snap_file["W1"], snap_file["W2"]],
            "b": [snap_file["b0"], snap_file["b1"], snap_file["b2"]],
        }
    )
    agent.tgt.copy_from(agent.q)
    pools = {
        "imports": [int(v) for v in snap_file["imports"]],
        "sections": [int(v) for v in snap_file["sections"]],
    }
    return cfg, agent, pools


def mutate_pe(root: Path, src: Path, dest: Path) -> dict:
    """Copy src, apply the saved DQN edits, and write dest. Does not run the PE."""
    root = Path(root)
    src = Path(src)
    dest = Path(dest)
    cfg, agent, pools = load_agent(root)
    vocab = json.loads((root / "data" / "lab_dataset" / "vocab.json").read_text(encoding="utf-8"))
    detectors = joblib.load(root / "models" / "lab_dataset" / "detectors.joblib")
    blackbox = detectors["RandomForest"]
    rng = np.random.default_rng(cfg.seed)
    env = MalwareEnv(cfg, blackbox, pools, rng)
    work = dest.parent / "work" / dest.stem
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    vector = vectorize_pe(src, vocab, cfg)
    _, info = agent.mutate(env, vector, rng, src, work, vocab)
    if env.pe_path is None or not Path(env.pe_path).is_file():
        raise RuntimeError("Khong tao duoc ban mutate.")
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(env.pe_path, dest)
    info["actions_named"] = [ACTIONS[i] for i in info.get("actions") or []]
    info["vector"] = env.state.copy()
    return info
