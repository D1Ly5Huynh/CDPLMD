"""DRL environment — 7 functionality-preserving actions (IF-MalEvade Table 3).

State is the 3523-d import+section bit vector. Original import 1-bits stay on.
Reward is paper eq. (1) on evasion, else 0.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import numpy as np

from .config import Config
from .detectors import malware_score

# Table 3 names. The first three draw candidates from the MalGAN pool.
ACTIONS = [
    "insert_import",
    "rename_section",
    "insert_section",
    "section_append",
    "upx_pack",
    "upx_unpack",
    "overly_append",
]


def _feature_name(vocab: dict, cfg: Config, feature: int | None) -> str | None:
    if feature is None:
        return None
    if feature < cfg.n_imports:
        names = vocab.get("imports") or []
        return names[feature] if feature < len(names) else None
    sec = feature - cfg.n_imports
    names = vocab.get("sections") or []
    return names[sec] if sec < len(names) else None


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
        self.pe_path = None
        self.origin_pe = None
        self.work_dir = None
        self.vocab = None
        self._editor = None
        self.edit_failures = 0

    def prepare_episode(self, src: Path, work_dir: Path, vocab: dict) -> None:
        """Copy one original PE into the work dir and bind Table 3 edits to it."""
        src = Path(src)
        work_dir = Path(work_dir)
        work_dir.mkdir(parents=True, exist_ok=True)
        for old in work_dir.iterdir():
            if old.is_file():
                old.unlink()
        dest = work_dir / src.name
        shutil.copy2(src, dest)
        self.origin_pe = dest
        self.bind_pe(dest, work_dir, vocab)

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
        if name == "insert_import":
            j = self._pick_one(self.pools.get("imports") or [])
            if j is not None:
                self.state[j] = 1.0
                self._edit_pe(name, j)
        elif name == "insert_section":
            j = self._pick_one(self.pools.get("sections") or [])
            if j is not None:
                self.state[j] = 1.0
                self._edit_pe(name, j)
        elif name == "rename_section" and self.cfg.n_sections > 0:
            sec = slice(self.cfg.n_imports, self.cfg.n_imports + self.cfg.n_sections)
            on = np.where(self.state[sec] >= 0.5)[0]
            off_pool = [
                i for i in (self.pools.get("sections") or []) if self.state[i] < 0.5
            ]
            if len(on) and off_pool:
                drop = int(on[self.rng.integers(0, len(on))])
                add = int(off_pool[self.rng.integers(0, len(off_pool))])
                drop_idx = self.cfg.n_imports + drop
                old_name = (
                    _feature_name(self.vocab, self.cfg, drop_idx) if self.vocab else None
                )
                self.state[drop_idx] = 0.0
                self.state[add] = 1.0
                self._edit_pe(name, add, old_section=old_name)
        elif name in ("section_append", "upx_pack", "upx_unpack", "overly_append"):
            # These four edit the file. The import/section vector changes only
            # when the rebuilt PE parses differently.
            self._edit_pe(name, None)
        return not np.array_equal(before, self.state)

    def bind_pe(self, path, work_dir, vocab: dict) -> None:
        self.pe_path = path
        self.work_dir = work_dir
        self.vocab = vocab

    def _edit_pe(self, action: str, feature: int | None, old_section: str | None = None) -> None:
        if self.pe_path is None or self.work_dir is None or self.vocab is None:
            return
        from .data import vectorize_pe
        from .pe_mutate import EditSession

        if self._editor is None:
            self._editor = EditSession()
        spec = _feature_name(self.vocab, self.cfg, feature)
        prev = Path(self.pe_path)
        try:
            edited = self._editor.apply(
                prev,
                action,
                self.work_dir,
                import_name=spec if action == "insert_import" else None,
                section_name=spec if action in ("insert_section", "rename_section") else None,
                old_section=old_section,
            )
            new_state = vectorize_pe(edited, self.vocab, self.cfg)
        except Exception:
            # The file did not take the edit. Drop the optimistic bit flip.
            self.edit_failures += 1
            try:
                self.state = vectorize_pe(prev, self.vocab, self.cfg)
            except Exception:
                pass
            return
        if (
            prev != edited
            and self.origin_pe is not None
            and prev != Path(self.origin_pe)
            and prev.exists()
        ):
            prev.unlink()
        self.pe_path = edited
        self.state = new_state

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
