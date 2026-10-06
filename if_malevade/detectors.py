from __future__ import annotations

import numpy as np
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import roc_auc_score
from sklearn.neural_network import MLPClassifier
from sklearn.tree import DecisionTreeClassifier

from .config import Config


def build_detectors(cfg: Config) -> dict:
    """Paper §IV: RF / GB / MLP / DT, sklearn defaults except MLP lr/epoch/batch."""
    return {
        "RandomForest": RandomForestClassifier(random_state=cfg.seed),
        "GradientBoosting": GradientBoostingClassifier(random_state=cfg.seed),
        "MLP": MLPClassifier(
            hidden_layer_sizes=(cfg.mlp_hidden,),
            max_iter=cfg.mlp_max_iter,
            batch_size=cfg.mlp_batch,
            learning_rate_init=cfg.mlp_lr,
            random_state=cfg.seed,
        ),
        "DecisionTree": DecisionTreeClassifier(random_state=cfg.seed),
    }


def fit_detectors(detectors: dict, X, y) -> dict:
    for clf in detectors.values():
        clf.fit(X, y)
    return detectors


def malware_score(clf, X: np.ndarray) -> np.ndarray:
    if hasattr(clf, "predict_proba"):
        proba = clf.predict_proba(X)
        classes = list(clf.classes_)
        if 1 in classes:
            return proba[:, classes.index(1)].astype(np.float32)
        return np.zeros(len(X), dtype=np.float32)
    return clf.predict(X).astype(np.float32)


def is_malware(clf, X: np.ndarray, threshold: float) -> np.ndarray:
    return malware_score(clf, X) >= threshold


def detection_rate(clf, X: np.ndarray, threshold: float) -> float:
    if len(X) == 0:
        return 0.0
    return float(is_malware(clf, X, threshold).mean())


def auc_of(clf, X: np.ndarray, y: np.ndarray) -> float:
    try:
        return float(roc_auc_score(y, malware_score(clf, X)))
    except ValueError:
        return float("nan")
