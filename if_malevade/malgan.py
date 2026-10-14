"""MalGAN-style influential-feature generator (Hu & Tan; IF-MalEvade §E).

Generator may only ADD bits (OR with the original malware vector) so original
malicious imports are preserved.
"""

from __future__ import annotations

import numpy as np
from tqdm import tqdm

from .config import Config
from .data import split_malware
from .detectors import is_malware
from .nn import MLP


def soft_or(malware: np.ndarray, gen: np.ndarray) -> np.ndarray:
    return malware + (1.0 - malware) * gen


def hard_or(malware: np.ndarray, gen: np.ndarray) -> np.ndarray:
    return np.maximum(malware, (gen >= 0.5).astype(np.float32))


class MalGAN:
    def __init__(self, cfg: Config, seed: int) -> None:
        d = cfg.n_features
        self.cfg = cfg
        self.G = MLP(
            [d + cfg.gan_noise, cfg.gan_hidden, d],
            hidden_act="leaky",
            out_act="sigmoid",
            leaky=cfg.leaky,
            lr=cfg.gan_lr,
            seed=seed,
            out_bias=cfg.gan_out_bias,
        )
        self.D = MLP(
            [d, cfg.gan_hidden, 1],
            hidden_act="leaky",
            out_act="sigmoid",
            leaky=cfg.leaky,
            lr=cfg.gan_lr,
            seed=seed + 1,
        )

    def generate(self, malware: np.ndarray, rng: np.random.Generator, hard: bool = True) -> np.ndarray:
        z = rng.normal(0.0, 1.0, size=(len(malware), self.cfg.gan_noise)).astype(np.float32)
        g, _ = self.G.forward(np.hstack([malware, z]))
        return hard_or(malware, g) if hard else soft_or(malware, g)

    def train(self, blackbox, X: np.ndarray, y: np.ndarray, rng: np.random.Generator) -> dict:
        mal, ben = split_malware(X, y)
        cfg = self.cfg
        hist = {"g_loss": [], "d_loss": [], "evade_batch": [], "mean_added": []}
        steps = max(1, int(np.ceil(len(mal) / cfg.gan_batch)))
        for epoch in tqdm(range(cfg.gan_epochs), desc="MalGAN"):
            perm = rng.permutation(len(mal))
            g_acc, d_acc, ev_acc, add_acc, n = 0.0, 0.0, 0.0, 0.0, 0
            for s in range(steps):
                sl = perm[s * cfg.gan_batch : (s + 1) * cfg.gan_batch]
                if len(sl) < 1:
                    continue
                m = mal[sl]
                b = ben[rng.integers(0, len(ben), size=len(m))]
                z = rng.normal(0.0, 1.0, size=(len(m), cfg.gan_noise)).astype(np.float32)
                g_out, g_cache = self.G.forward(np.hstack([m, z]))
                m_soft = soft_or(m, g_out)
                m_hard = hard_or(m, g_out)

                # Discriminator fits the frozen black-box detector.
                xb = np.vstack([b, m_hard])
                yb = is_malware(blackbox, xb, cfg.threshold).astype(np.float32).reshape(-1, 1)
                d_pred, d_cache = self.D.forward(xb)
                d_loss = float(np.mean((d_pred - yb) ** 2))
                self.D.backward(2.0 * (d_pred - yb) / len(xb), d_cache)

                # Generator wants D(m_adv) → benign (0). Freeze D weights.
                d_on_g, d_g_cache = self.D.forward(m_soft)
                eps = 1e-6
                dL_dD = (1.0 / np.clip(1.0 - d_on_g, eps, None)) / len(m_soft)
                dL_dx = self.D.backward(dL_dD, d_g_cache, freeze=True)
                # Only bits that were off can change. Sparsity pushes those toward 0
                # so a flooded OR is not a free evasion.
                new_bits = 1.0 - m
                dL_dg = dL_dx * new_bits
                if cfg.gan_sparsity > 0:
                    dL_dg = dL_dg + (cfg.gan_sparsity * new_bits) / g_out.size
                self.G.backward(dL_dg, g_cache)

                added = ((g_out >= 0.5) & (m < 0.5)).sum(axis=1)
                g_acc += float(np.mean(-np.log(np.clip(1.0 - d_on_g, eps, 1.0))))
                d_acc += d_loss
                ev_acc += float(1.0 - yb[len(m) :].mean())
                add_acc += float(added.mean())
                n += 1
            hist["g_loss"].append(g_acc / max(n, 1))
            hist["d_loss"].append(d_acc / max(n, 1))
            hist["evade_batch"].append(ev_acc / max(n, 1))
            hist["mean_added"].append(add_acc / max(n, 1))
        return hist

    def influential_pools(
        self,
        malware: np.ndarray,
        benign: np.ndarray,
        blackbox,
        rng: np.random.Generator,
        cfg: Config,
    ) -> dict:
        adv = self.generate(malware, rng, hard=True)
        ok = ~is_malware(blackbox, adv, cfg.threshold)
        added_all = (adv > 0.5) & (malware < 0.5)
        counts = added_all.sum(axis=1)
        # A sample that flips hundreds of bits did not find influential features.
        sparse = ok & (counts <= cfg.gan_max_added)
        if sparse.any():
            added = added_all[sparse]
            freq = added.mean(axis=0)
            mean_added = float(counts[sparse].mean())
        else:
            freq = np.zeros(malware.shape[1], dtype=np.float32)
            mean_added = 0.0
        n_imp = cfg.n_imports
        n_sec = cfg.n_sections
        imp_rank = np.argsort(-freq[:n_imp])
        sec_rank = (
            np.argsort(-freq[n_imp : n_imp + n_sec]) if n_sec else np.array([], dtype=int)
        )
        imports = [int(i) for i in imp_rank if freq[int(i)] > 0]
        sections = [
            int(n_imp + i) for i in sec_rank if n_sec and freq[int(n_imp + i)] > 0
        ]
        return {
            "imports": imports,
            "sections": sections,
            "freq": freq,
            "success_rate": float(ok.mean()) if len(ok) else 0.0,
            "sparse_success_rate": float(sparse.mean()) if len(sparse) else 0.0,
            "mean_added": mean_added,
            "mean_added_all": float(counts[ok].mean()) if ok.any() else 0.0,
        }
