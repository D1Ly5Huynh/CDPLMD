"""Deep Q-Network agent (Fang DQEAF / IF-MalEvade §F)."""

from __future__ import annotations

from collections import deque

import numpy as np
from tqdm import tqdm

from .config import Config
from .env import MalwareEnv
from .nn import MLP


class Replay:
    def __init__(self, cap: int) -> None:
        self.s = deque(maxlen=cap)
        self.a = deque(maxlen=cap)
        self.r = deque(maxlen=cap)
        self.ns = deque(maxlen=cap)
        self.d = deque(maxlen=cap)

    def __len__(self) -> int:
        return len(self.s)

    def push(self, s, a, r, ns, done) -> None:
        self.s.append(s)
        self.a.append(a)
        self.r.append(r)
        self.ns.append(ns)
        self.d.append(done)

    def sample(self, n: int, rng: np.random.Generator):
        idx = rng.choice(len(self.s), size=n, replace=False)
        s = np.stack([self.s[i] for i in idx])
        a = np.array([self.a[i] for i in idx], dtype=np.int64)
        r = np.array([self.r[i] for i in idx], dtype=np.float32)
        ns = np.stack([self.ns[i] for i in idx])
        d = np.array([self.d[i] for i in idx], dtype=np.float32)
        return s, a, r, ns, d


class DQNAgent:
    def __init__(self, cfg: Config, seed: int) -> None:
        self.cfg = cfg
        sizes = [cfg.n_features, cfg.dqn_h1, cfg.dqn_h2, cfg.n_actions]
        self.q = MLP(sizes, hidden_act="relu", out_act="identity", lr=cfg.dqn_lr, seed=seed)
        self.tgt = MLP(sizes, hidden_act="relu", out_act="identity", lr=cfg.dqn_lr, seed=seed)
        self.tgt.copy_from(self.q)
        self.replay = Replay(cfg.buffer_size)
        self.learn_steps = 0

    def act(self, state: np.ndarray, epsilon: float, rng: np.random.Generator) -> int:
        if rng.random() < epsilon:
            return int(rng.integers(0, self.cfg.n_actions))
        q, _ = self.q.forward(state[None, :])
        return int(np.argmax(q[0]))

    def learn(self, rng: np.random.Generator) -> float:
        cfg = self.cfg
        if len(self.replay) < cfg.warmup:
            return 0.0
        s, a, r, ns, d = self.replay.sample(cfg.dqn_batch, rng)
        q, cache = self.q.forward(s)
        qn, _ = self.tgt.forward(ns)
        max_next = qn.max(axis=1)
        target = q.copy()
        target[np.arange(len(a)), a] = r + cfg.gamma * max_next * (1.0 - d)
        loss = float(np.mean((q - target) ** 2))
        self.q.backward(2.0 * (q - target) / len(s), cache)
        self.learn_steps += 1
        if self.learn_steps % cfg.target_sync == 0:
            self.tgt.copy_from(self.q)
        return loss

    def train(
        self,
        env: MalwareEnv,
        malware: np.ndarray,
        rng: np.random.Generator,
        paths: list | None = None,
        work_dir=None,
        vocab: dict | None = None,
    ) -> dict:
        cfg = self.cfg
        hist = {"return": [], "evade": [], "loss": [], "turns": []}
        for ep in tqdm(range(cfg.episodes), desc="DQN"):
            frac = ep / max(cfg.episodes - 1, 1)
            eps = cfg.epsilon_start + (cfg.epsilon_end - cfg.epsilon_start) * frac
            i = int(rng.integers(0, len(malware)))
            sample = malware[i]
            if paths is not None and work_dir is not None and vocab is not None:
                env.prepare_episode(paths[i], work_dir, vocab)
            s = env.reset(sample)
            total, last_loss, evaded, turns = 0.0, 0.0, False, 0
            for _ in range(cfg.max_turn):
                a = self.act(s, eps, rng)
                ns, r, done, info = env.step(a)
                self.replay.push(s, a, r, ns, done)
                last_loss = self.learn(rng)
                s = ns
                total += r
                turns = info["turn"]
                if done:
                    evaded = info["evaded"]
                    break
            hist["return"].append(total)
            hist["evade"].append(float(evaded))
            hist["loss"].append(last_loss)
            hist["turns"].append(turns)
        return hist

    def mutate(
        self,
        env: MalwareEnv,
        sample: np.ndarray,
        rng: np.random.Generator,
        src=None,
        work_dir=None,
        vocab: dict | None = None,
    ) -> tuple[np.ndarray, dict]:
        if src is not None and work_dir is not None and vocab is not None:
            env.prepare_episode(src, work_dir, vocab)
        s = env.reset(sample)
        info = {"evaded": False, "turn": 0, "actions": []}
        for _ in range(self.cfg.max_turn):
            a = self.act(s, 0.0, rng)
            s, r, done, step = env.step(a)
            info["actions"].append(int(a))
            info["turn"] = step["turn"]
            info["evaded"] = step["evaded"]
            if done:
                break
        return env.state.copy(), info
