"""Lab baselines for the paper's MalFox and MAB-Malware columns.

Both methods edit the 50 eval PEs with the same Table 3 actions as DQN.
MAB-Malware follows Song et al.: one Beta arm per action, Thompson sampling,
reward 1 only when the black-box score falls under the lab threshold.
MalFox follows Zhong et al. only in the outer loop: a small policy emits a
path of at most three actions, then the PE editor applies that path.
Obfusmal / Stealmal / Hollowmal are not reimplemented.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import numpy as np

from .config import Config
from .detectors import malware_score
from .env import ACTIONS, MalwareEnv

MAB_PULLS = 10
MALFOX_STEPS = 3
N_ARMS = len(ACTIONS)


def benign_pools(X: np.ndarray, y: np.ndarray, cfg: Config) -> dict:
    """Import and section columns that actually show up on benign rows."""
    ben = X[np.asarray(y) == 0]
    if len(ben) == 0:
        return {"imports": [], "sections": []}
    imp = ben[:, : cfg.n_imports].mean(axis=0)
    sec = ben[:, cfg.n_imports : cfg.n_imports + cfg.n_sections].mean(axis=0)
    imp_idx = [int(i) for i in np.argsort(imp)[-40:] if imp[i] > 0]
    sec_idx = [
        int(cfg.n_imports + i) for i in np.argsort(sec)[-16:] if sec[i] > 0
    ]
    return {"imports": imp_idx, "sections": sec_idx}


def choose_arm(alpha: np.ndarray, beta: np.ndarray, rng: np.random.Generator) -> int:
    """Thompson sampling: pull the arm with the largest Beta draw."""
    draw = rng.beta(alpha.astype(np.float64), beta.astype(np.float64))
    return int(np.argmax(draw))


def _policy_features(state: np.ndarray, score: float, cfg: Config) -> np.ndarray:
    imp = state[: cfg.n_imports]
    sec = state[cfg.n_imports : cfg.n_imports + cfg.n_sections]
    return np.array(
        [float(imp.mean()), float(sec.mean()), float(score), 1.0],
        dtype=np.float32,
    )


def train_malfox_policy(
    detector,
    malware: np.ndarray,
    pools: dict,
    cfg: Config,
    rng: np.random.Generator,
    updates: int = 256,
) -> np.ndarray:
    """REINFORCE a linear policy. No PE bytes; only the feature vector moves."""
    env = MalwareEnv(cfg, detector, pools, rng)
    weight = np.zeros((N_ARMS, 4), dtype=np.float32)
    weight[4, 3] = 1.2
    weight[0, 3] = 0.8
    weight[1, 3] = 0.6
    for _ in range(updates):
        sample = malware[int(rng.integers(0, len(malware)))]
        env.reset(sample)
        score0 = float(malware_score(detector, sample[None, :])[0])
        feats = _policy_features(env.state, score0, cfg)
        logits = weight @ feats
        shifted = logits - float(np.max(logits))
        prob = np.exp(shifted)
        prob /= float(prob.sum())
        chosen = []
        for _step in range(MALFOX_STEPS):
            arm = int(rng.choice(N_ARMS, p=prob))
            env.step(arm)
            chosen.append(arm)
        score1 = float(malware_score(detector, env.state[None, :])[0])
        reward = score0 - score1
        grad = -prob
        for arm in chosen:
            grad[arm] += 1.0
        weight += (0.05 * reward * np.outer(grad, feats)).astype(np.float32)
    return weight


def malfox_path(weight: np.ndarray, state: np.ndarray, score: float, cfg: Config) -> list[int]:
    feats = _policy_features(state, score, cfg)
    order = np.argsort(-(weight @ feats))
    return [int(a) for a in order[:MALFOX_STEPS]]


def _copy_mutant(env: MalwareEnv, dest: Path) -> bool:
    src = env.pe_path
    if src is None or not Path(src).is_file():
        return False
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)
    return True


def run_mab_thompson(env, samples, paths, mut_dir, work, vocab, rng) -> dict:
    """Thompson sampling with a posterior updated after every pull."""
    alpha = np.ones(N_ARMS, dtype=np.float64)
    beta = np.ones(N_ARMS, dtype=np.float64)
    mut_dir.mkdir(parents=True, exist_ok=True)
    adv = np.zeros_like(samples)
    turns = []
    evaded_n = 0
    written = 0
    saved_max = env.cfg.max_turn
    env.cfg.max_turn = MAB_PULLS
    try:
        for i, src in enumerate(paths):
            env.prepare_episode(src, work, vocab)
            env.reset(samples[i])
            info = {"evaded": False, "turn": 0, "score": None}
            done = False
            while not done:
                arm = choose_arm(alpha, beta, rng)
                score_before = float(malware_score(env.detector, env.state[None, :])[0])
                _state, _reward, done, info = env.step(arm)
                score_after = float(info.get("score") if info.get("score") is not None else score_before)
                if info.get("evaded") or score_after + 1e-6 < score_before:
                    alpha[arm] += 1.0
                else:
                    beta[arm] += 1.0
            adv[i] = env.state
            evaded_n += int(bool(info.get("evaded")))
            turns.append(int(info.get("turn") or 0))
            if _copy_mutant(env, mut_dir / f"{src.stem}.mut.exe"):
                written += 1
            print(
                f"mab {i + 1}/{len(paths)} evaded={int(bool(info.get('evaded')))} "
                f"turns={info.get('turn')} score={info.get('score')}",
                flush=True,
            )
    finally:
        env.cfg.max_turn = saved_max
    return {
        "adv": adv,
        "n": int(len(paths)),
        "n_written": written,
        "evade": float(evaded_n / len(paths)) if paths else 0.0,
        "mean_turns": float(np.mean(turns)) if turns else 0.0,
        "edit_failures": int(env.edit_failures),
        "pulls": MAB_PULLS,
        "arms": list(ACTIONS),
        "alpha": alpha.tolist(),
        "beta": beta.tolist(),
    }


def run_malfox(env, samples, paths, mut_dir, work, vocab, weight: np.ndarray) -> dict:
    saved_max = env.cfg.max_turn
    env.cfg.max_turn = MALFOX_STEPS
    mut_dir.mkdir(parents=True, exist_ok=True)
    adv = np.zeros_like(samples)
    turns = []
    evaded_n = 0
    written = 0
    try:
        for i, src in enumerate(paths):
            env.prepare_episode(src, work, vocab)
            env.reset(samples[i])
            score0 = float(malware_score(env.detector, samples[i][None, :])[0])
            path = malfox_path(weight, env.state, score0, env.cfg)
            info = {"evaded": False, "turn": 0, "score": score0}
            for arm in path:
                _state, _reward, done, info = env.step(int(arm))
                if done:
                    break
            adv[i] = env.state
            evaded_n += int(bool(info.get("evaded")))
            turns.append(int(info.get("turn") or 0))
            if _copy_mutant(env, mut_dir / f"{src.stem}.mut.exe"):
                written += 1
            print(
                f"malfox {i + 1}/{len(paths)} evaded={int(bool(info.get('evaded')))} "
                f"turns={info.get('turn')} score={info.get('score')} path={path}",
                flush=True,
            )
    finally:
        env.cfg.max_turn = saved_max
    return {
        "adv": adv,
        "n": int(len(paths)),
        "n_written": written,
        "evade": float(evaded_n / len(paths)) if paths else 0.0,
        "mean_turns": float(np.mean(turns)) if turns else 0.0,
        "edit_failures": int(env.edit_failures),
        "steps": MALFOX_STEPS,
        "arms": list(ACTIONS),
    }
