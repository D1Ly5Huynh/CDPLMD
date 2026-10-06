import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from if_malevade.config import Config
from if_malevade.cuckoo_client import signature_names, signatures_match
from if_malevade.vt_client import engine_counts, table6_7
from if_malevade.env import ACTIONS, success_reward
from if_malevade.malgan import hard_or, soft_or


def test_feature_dim_is_paper_3523():
    cfg = Config()
    assert cfg.n_imports == 3269
    assert cfg.n_sections == 254
    assert cfg.n_features == 3523
    assert cfg.n_actions == 7
    assert len(ACTIONS) == 7
    assert cfg.gan_epochs == 100
    assert cfg.episodes == 500
    assert cfg.max_turn == 50
    assert cfg.gamma == 0.98
    assert cfg.threshold == 0.8
    assert cfg.eval_n == 500
    assert not hasattr(cfg, "n_aux")
    assert not hasattr(cfg, "reward_shaping")


def test_reward_turn1_is_20():
    assert abs(success_reward(1, 50) - 20.0) < 1e-9


def test_reward_stays_positive():
    for t in range(1, 51):
        assert success_reward(t, 50) > 0.0


def test_or_never_drops_original_ones():
    m = np.array([[1.0, 0.0, 1.0, 0.0]], dtype=np.float32)
    g = np.array([[0.1, 0.9, 0.2, 0.4]], dtype=np.float32)
    h = hard_or(m, g)
    s = soft_or(m, g)
    assert h[0, 0] == 1.0 and h[0, 2] == 1.0
    assert h[0, 1] == 1.0
    assert s[0, 0] == 1.0 and s[0, 2] == 1.0
    assert s[0, 1] > 0.8


def test_cuckoo_signature_recall():
    orig = {"signatures": [{"name": "creates_exe"}, {"name": "allocates_rwx"}]}
    keep = {"signatures": [{"name": "creates_exe"}, {"name": "allocates_rwx"}, {"name": "extra"}]}
    drop = {"signatures": [{"name": "creates_exe"}]}
    assert signatures_match(orig, keep, min_recall=1.0)
    assert not signatures_match(orig, drop, min_recall=1.0)
    assert signature_names(orig) == {"creates_exe", "allocates_rwx"}


def test_vt_eq3_engine_counts():
    report = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 12, "undetected": 49, "harmless": 0, "suspicious": 0},
                "last_analysis_results": {
                    "A": {"category": "malicious"},
                    "B": {"category": "undetected"},
                    "C": {"category": "malicious"},
                },
            }
        }
    }
    c = engine_counts(report)
    assert c["n"] == 2
    assert c["N"] == 3
    orig = {
        "n_ok": 1,
        "rows": [{"ok": True, "sha256": "a" * 64, "n": 40, "detection_rate": 40 / 61}],
    }
    adv = {
        "n_ok": 1,
        "rows": [{"ok": True, "sha256": "b" * 64, "parent_sha256": "a" * 64, "n": 10}],
    }
    t6, t7 = table6_7(orig, adv, n_engines_paper=61)
    assert t7["n_pairs"] == 1
    assert abs(t7["evasion_rate"]["mean"] - (40 - 10) / 40) < 1e-9
    assert t6["n_engines_paper"] == 61


if __name__ == "__main__":
    test_feature_dim_is_paper_3523()
    test_reward_turn1_is_20()
    test_reward_stays_positive()
    test_or_never_drops_original_ones()
    test_cuckoo_signature_recall()
    test_vt_eq3_engine_counts()
    print("ok")
