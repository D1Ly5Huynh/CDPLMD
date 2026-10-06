"""DRL environment — 7 functionality-preserving actions (IF-MalEvade Table 3).

State is the 3523-d import+section bit vector. Original import 1-bits stay on.
Reward is paper eq. (1) on evasion, else 0.
"""

from __future__ import annotations

import numpy as np

from .config import Config
from .detectors import malware_score

ACTIONS = [
    "add_import",
    "add_section",
    "add_unused_bytes",
    "rename_section",
    "upx_pack",
    "upx_unpack",
    "append_bytes",
]


def success_reward(turn: int, max_turn: int) -> float:
    """Paper eq. (1): r_t = 20 * 100^(-(TURN-1)/MAXTURN) when labelled benign."""
    return float(20.0 * (100.0 ** (-(turn - 1) / max_turn)))


class MalwareEnv:
    def __init__(self, cfg: Config, detector, pools: dict, rng: np.random.Generator) -> None:
        self.cfg = cfg
        self.detector = detector
        self.pools = pools
        self.rng = rng
        self.state = None
        self.turn = 0
        self.origin = None

    def reset(self, sample: np.ndarray) -> np.ndarray:
        self.origin = sample.astype(np.float32, copy=True)
        self.state = sample.astype(np.float32, copy=True)
        self.turn = 0
        return self.state.copy()

    def _pick_one(self, indices: list[int]) -> int | None:
        zeros = [i for i in indices if self.state[i] < 0.5]
        if not zeros:
            return None
        return int(zeros[int(self.rng.integers(0, len(zeros)))])

    def _step_action(self, action: int) -> bool:
        name = ACTIONS[action]
        before = self.state.copy()
        if name == "add_import":
            j = self._pick_one(self.pools.get("imports") or [])
            if j is not None:
                self.state[j] = 1.0
        elif name == "add_section":
            j = self._pick_one(self.pools.get("sections") or [])
            if j is not None:
                self.state[j] = 1.0
        elif name == "rename_section" and self.cfg.n_sections > 0:
            sec = slice(self.cfg.n_imports, self.cfg.n_imports + self.cfg.n_sections)
            on = np.where(self.state[sec] >= 0.5)[0]
            off_pool = [
                i for i in (self.pools.get("sections") or []) if self.state[i] < 0.5
            ]
            if len(on) and off_pool:
                drop = int(on[self.rng.integers(0, len(on))])
                add = int(off_pool[self.rng.integers(0, len(off_pool))])
                self.state[self.cfg.n_imports + drop] = 0.0
                self.state[add] = 1.0
        # add_unused_bytes / upx_pack / upx_unpack / append_bytes change the PE
        # (pe_mutate.py) but not the 3523-d import/section name vector.
        return not np.array_equal(before, self.state)

    def step(self, action: int) -> tuple[np.ndarray, float, bool, dict]:
        self.turn += 1
        self._step_action(int(action))
        after = float(malware_score(self.detector, self.state[None, :])[0])
        evaded = after < self.cfg.threshold
        done = evaded or self.turn >= self.cfg.max_turn
        reward = success_reward(self.turn, self.cfg.max_turn) if evaded else 0.0
        return (
            self.state.copy(),
            float(reward),
            bool(done),
            {"evaded": evaded, "turn": self.turn, "score": after},
        )
