"""Minimal NumPy MLP + Adam — used for MalGAN and DQN (no PyTorch required)."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np


def _leaky(z: np.ndarray, a: float) -> np.ndarray:
    return np.where(z > 0, z, a * z)


def _dleaky(z: np.ndarray, a: float) -> np.ndarray:
    return np.where(z > 0, 1.0, a).astype(np.float32)


def _relu(z: np.ndarray) -> np.ndarray:
    return np.maximum(z, 0.0)


def _drelu(z: np.ndarray) -> np.ndarray:
    return (z > 0).astype(np.float32)


def _sigmoid(z: np.ndarray) -> np.ndarray:
    z = np.clip(z, -40.0, 40.0)
    return 1.0 / (1.0 + np.exp(-z))


@dataclass
class AdamState:
    m_w: list
    v_w: list
    m_b: list
    v_b: list
    t: int = 0


class MLP:
    def __init__(
        self,
        sizes: list[int],
        hidden_act: str = "leaky",
        out_act: str = "sigmoid",
        leaky: float = 0.2,
        lr: float = 1e-3,
        seed: int = 0,
        out_bias: float = 0.0,
    ) -> None:
        rng = np.random.default_rng(seed)
        self.sizes = sizes
        self.hidden_act = hidden_act
        self.out_act = out_act
        self.leaky = leaky
        self.lr = lr
        self.W: list[np.ndarray] = []
        self.b: list[np.ndarray] = []
        pairs = list(zip(sizes[:-1], sizes[1:]))
        for i, (a, c) in enumerate(pairs):
            self.W.append(rng.normal(0.0, np.sqrt(2.0 / a), (a, c)).astype(np.float32))
            bias = np.zeros(c, dtype=np.float32)
            if i == len(pairs) - 1 and out_bias != 0.0:
                bias[:] = np.float32(out_bias)
            self.b.append(bias)
        self.adam = AdamState(
            m_w=[np.zeros_like(w) for w in self.W],
            v_w=[np.zeros_like(w) for w in self.W],
            m_b=[np.zeros_like(b) for b in self.b],
            v_b=[np.zeros_like(b) for b in self.b],
        )

    def _act(self, z: np.ndarray, last: bool) -> np.ndarray:
        if last:
            if self.out_act == "sigmoid":
                return _sigmoid(z)
            if self.out_act == "identity":
                return z
            return _relu(z)
        if self.hidden_act == "relu":
            return _relu(z)
        return _leaky(z, self.leaky)

    def _dact(self, z: np.ndarray, last: bool) -> np.ndarray:
        if last:
            if self.out_act == "sigmoid":
                s = _sigmoid(z)
                return s * (1.0 - s)
            if self.out_act == "identity":
                return np.ones_like(z, dtype=np.float32)
            return _drelu(z)
        if self.hidden_act == "relu":
            return _drelu(z)
        return _dleaky(z, self.leaky)

    def forward(self, x: np.ndarray) -> tuple[np.ndarray, dict]:
        a = x.astype(np.float32, copy=False)
        zs: list[np.ndarray] = []
        acts: list[np.ndarray] = [a]
        last = len(self.W) - 1
        for i, (W, b) in enumerate(zip(self.W, self.b)):
            z = a @ W + b
            a = self._act(z, i == last)
            zs.append(z)
            acts.append(a)
        return a, {"zs": zs, "acts": acts}

    def predict(self, x: np.ndarray) -> np.ndarray:
        y, _ = self.forward(x)
        return y

    def backward(self, dL_dy: np.ndarray, cache: dict, freeze: bool = False) -> np.ndarray:
        """Backprop. Returns dL/dx. Updates weights unless freeze=True."""
        g = np.asarray(dL_dy, dtype=np.float32)
        last = len(self.W) - 1
        dW = [None] * len(self.W)
        db = [None] * len(self.b)
        for i in range(last, -1, -1):
            g = g * self._dact(cache["zs"][i], i == last)
            a_prev = cache["acts"][i]
            dW[i] = a_prev.T @ g
            db[i] = g.sum(axis=0)
            g = g @ self.W[i].T
        if not freeze:
            self._adam_step(dW, db)
        return g

    def _adam_step(self, dW, db, beta1=0.9, beta2=0.999, eps=1e-8) -> None:
        st = self.adam
        st.t += 1
        lr_t = self.lr * np.sqrt(1 - beta2**st.t) / (1 - beta1**st.t)
        for i in range(len(self.W)):
            gw = dW[i].astype(np.float32)
            gb = db[i].astype(np.float32)
            st.m_w[i] = beta1 * st.m_w[i] + (1 - beta1) * gw
            st.v_w[i] = beta2 * st.v_w[i] + (1 - beta2) * (gw * gw)
            st.m_b[i] = beta1 * st.m_b[i] + (1 - beta1) * gb
            st.v_b[i] = beta2 * st.v_b[i] + (1 - beta2) * (gb * gb)
            self.W[i] -= lr_t * st.m_w[i] / (np.sqrt(st.v_w[i]) + eps)
            self.b[i] -= lr_t * st.m_b[i] / (np.sqrt(st.v_b[i]) + eps)

    def snapshot(self) -> dict:
        return {
            "sizes": self.sizes,
            "hidden_act": self.hidden_act,
            "out_act": self.out_act,
            "leaky": self.leaky,
            "W": [w.copy() for w in self.W],
            "b": [b.copy() for b in self.b],
        }

    def load_snapshot(self, snap: dict) -> None:
        self.W = [w.copy() for w in snap["W"]]
        self.b = [b.copy() for b in snap["b"]]

    def copy_from(self, other: "MLP") -> None:
        self.load_snapshot(other.snapshot())
