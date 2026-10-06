from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd

from .detectors import detection_rate


def odr_adr(clf, X_orig: np.ndarray, X_adv: np.ndarray, threshold: float) -> dict:
    return {
        "ODR": detection_rate(clf, X_orig, threshold),
        "ADR": detection_rate(clf, X_adv, threshold),
    }


def evasion_rate(n_org: np.ndarray, n_adv: np.ndarray) -> np.ndarray:
    """Paper eq. (4): (N_org - N_adv) / N_org per sample. For VirusTotal only."""
    n_org = np.asarray(n_org, dtype=np.float32)
    n_adv = np.asarray(n_adv, dtype=np.float32)
    return np.maximum((n_org - n_adv) / np.clip(n_org, 1.0, None), 0.0)


def detection_rate_engines(hits: np.ndarray, n_engines: int) -> np.ndarray:
    """Paper eq. (3): n / N per sample. For VirusTotal only."""
    return hits.astype(np.float32) / n_engines


def table4_frame(rows: dict) -> pd.DataFrame:
    return pd.DataFrame(rows).T.rename_axis("detector").reset_index()


def save_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, default=_json_default), encoding="utf-8")


def _json_default(o):
    if isinstance(o, (np.floating, np.integer)):
        return float(o) if isinstance(o, np.floating) else int(o)
    if isinstance(o, np.ndarray):
        return o.tolist()
    raise TypeError(type(o))
