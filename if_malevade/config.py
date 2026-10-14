from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class Config:
    """Hyper-parameters from IF-MalEvade (IEEE Access 2023) §III–IV."""

    name: str = "paper"
    seed: int = 42
    # Paper Table 2 is 25000 / 10000 / test 1000 / eval 500.
    # Lab scale is that table / 10: 2500 malware + 1000 benign.
    scale: int = 10
    n_imports: int = 3269
    n_sections: int = 254
    n_malware: int = 2500
    n_benign: int = 1000
    n_test_malware: int = 100
    gan_hidden: int = 256
    gan_noise: int = 10
    gan_epochs: int = 100
    gan_batch: int = 32
    gan_lr: float = 1e-3
    # Last-layer bias so sigmoid starts near 0. A zero bias flips ~half the bits.
    gan_out_bias: float = -4.0
    # Weight on bits the generator turns on. Flooded evasions never enter the pool.
    gan_sparsity: float = 1.0
    gan_max_added: int = 32
    leaky: float = 0.2
    dqn_h1: int = 256
    dqn_h2: int = 64
    gamma: float = 0.98
    episodes: int = 500
    max_turn: int = 50
    dqn_lr: float = 1e-3
    epsilon_start: float = 1.0
    epsilon_end: float = 0.05
    buffer_size: int = 8000
    dqn_batch: int = 64
    warmup: int = 256
    target_sync: int = 40
    threshold: float = 0.8
    # Half of the test row, same fraction as paper eval 500 of 1000.
    eval_n: int = 50
    retrain_frac: float = 0.5
    mlp_hidden: int = 100
    mlp_max_iter: int = 150
    mlp_batch: int = 50
    mlp_lr: float = 3e-4
    cuckoo_enabled: bool = True
    cuckoo_url: str = "http://127.0.0.1:8090"
    cuckoo_timeout: int = 20
    vt_enabled: bool = True
    vt_n_engines: int = 61
    vt_rate_sleep: float = 15.0
    out_dir: str = "results"
    model_dir: str = "models"

    @property
    def n_features(self) -> int:
        return self.n_imports + self.n_sections

    @property
    def n_actions(self) -> int:
        return 7

    def to_dict(self) -> dict:
        d = asdict(self)
        d["n_features"] = self.n_features
        d["n_actions"] = self.n_actions
        d["paper_n_malware"] = 25_000
        d["paper_n_benign"] = 10_000
        d["paper_n_test_malware"] = 1_000
        d["paper_eval_n"] = 500
        return d

    def resolve(self, root: Path) -> "Config":
        self.out_dir = str(root / self.out_dir)
        self.model_dir = str(root / self.model_dir)
        return self
