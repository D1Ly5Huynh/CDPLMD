import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from if_malevade.config import Config
from if_malevade.cuckoo_client import (
    CuckooClient,
    encode_multipart,
    signature_names,
    signatures_match,
)
from if_malevade.vt_client import (
    engine_counts,
    select_eval_hashes,
    table6_7,
    vt_job_paths,
)
from if_malevade.baselines import choose_arm
from if_malevade.env import ACTIONS, success_reward
from if_malevade.malgan import MalGAN, hard_or, soft_or
from if_malevade.data import complete_section_vocab, pe_split
from if_malevade.pipeline import assert_lab_scale, sha_list


def test_section_vocab_pads_to_paper_width():
    observed = [".text", ".data", ".rsrc"]
    sections = complete_section_vocab(observed, width=8)
    assert sections[:3] == observed
    assert len(sections) == 8
    assert len(set(sections)) == 8
    assert ".ifmimp" not in sections
    assert all(len(name.encode("utf-8")) <= 8 for name in sections[3:])


def test_thompson_picks_the_arm_that_pays():
    alpha = np.ones(7)
    beta = np.full(7, 40.0)
    alpha[2] = 80.0
    beta[2] = 1.0
    rng = np.random.default_rng(0)
    picks = [choose_arm(alpha, beta, rng) for _ in range(30)]
    assert picks.count(2) > 25


def test_feature_dim_is_paper_3523():
    cfg = Config()
    assert cfg.n_imports == 3269
    assert cfg.n_sections == 254
    assert cfg.n_features == 3523
    assert cfg.n_actions == 7
    assert ACTIONS == [
        "insert_import",
        "rename_section",
        "insert_section",
        "section_append",
        "upx_pack",
        "upx_unpack",
        "overly_append",
    ]
    assert cfg.gan_epochs == 100
    assert cfg.episodes == 500
    assert cfg.max_turn == 50
    assert cfg.gamma == 0.98
    assert cfg.threshold == 0.8
    # Lab: 2500 malware + 1000 benign. Test 100, eval 50 (paper holdout fraction).
    assert cfg.scale == 10
    assert cfg.n_malware == 2500
    assert cfg.n_benign == 1000
    assert cfg.n_test_malware == 100
    assert cfg.eval_n == 50
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


class _Resp:
    def __init__(self, payload: dict):
        self._raw = __import__("json").dumps(payload).encode()
        self.status = 200

    def read(self):
        return self._raw

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_cuckoo3_submit_and_signature_gate():
    """Cuckoo 3 ids are analysis strings. A failed analysis is not a match."""
    from unittest.mock import patch

    body, ctype = encode_multipart({"settings": '{"timeout":120}'}, 'a"b.exe', b"MZ")
    assert ctype.startswith("multipart/form-data; boundary=")
    assert b'filename="ab.exe"' in body
    assert b'"timeout":120' in body
    assert b"\r\n\r\nMZ\r\n--" in body

    polls = {"n": 0}

    def urlopen(req, timeout=0):
        url = req.full_url
        if url.endswith("/submit/file"):
            assert b"windows" in req.data
            if b"MZ-ORIG" in req.data:
                assert b'filename="sample.exe"' in req.data
            else:
                assert b'filename="sample.mut.exe"' in req.data
            aid = "orig" if b"MZ-ORIG" in req.data else "adv"
            return _Resp({"analysis_id": aid, "settings": {}})
        if url.endswith("/analysis/orig"):
            polls["n"] += 1
            state = "tasks_pending" if polls["n"] == 1 else "finished"
            return _Resp({"id": "orig", "state": state, "tasks": [{"id": "task_1"}]})
        if url.endswith("/analysis/adv"):
            return _Resp({"id": "adv", "state": "fatal_error", "tasks": [], "errors": {"fatal": ["boot"]}})
        if url.endswith("/analysis/orig/task/task_1/post"):
            return _Resp({"signatures": [{"name": "creates_exe"}]})
        raise AssertionError(url)

    client = CuckooClient(base_url="http://cuckoo.test", timeout=5)
    with patch("if_malevade.cuckoo_client.urlopen", urlopen):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            orig = Path(tmp) / "sample.exe"
            adv = Path(tmp) / "sample.mut.exe"
            orig.write_bytes(b"MZ-ORIG")
            adv.write_bytes(b"MZ-ADV")
            out = client.compare_pair(orig, adv, poll=0, max_wait=30)
    assert out["orig_submit"]["analysis_id"] == "orig"
    assert out["adv_submit"]["analysis_id"] == "adv"
    assert out["orig_state"] == "finished"
    assert out["adv_state"] == "fatal_error"
    assert out["match"] is False
    assert out["error"] == "analysis_not_finished"
    assert out["orig_signatures"] == ["creates_exe"]


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
    analysis = {
        "data": {
            "type": "analysis",
            "attributes": {
                "status": "completed",
                "stats": {"malicious": 10, "undetected": 50},
                "results": {
                    "A": {"category": "malicious"},
                    "B": {"category": "undetected"},
                },
            },
        }
    }
    counted = engine_counts(analysis)
    assert counted["n"] == 1
    assert counted["N"] == 2
    orig = {
        "n_ok": 1,
        "rows": [{"ok": True, "sha256": "a" * 64, "n": 40, "detection_rate": 40 / 61}],
    }
    adv = {
        "n_ok": 1,
        "rows": [{
            "ok": True,
            "sha256": "b" * 64,
            "parent_sha256": "a" * 64,
            "n": 10,
            "N": 75,
            "detection_rate": 10 / 75,
        }],
    }
    t6, t7 = table6_7(orig, adv, n_engines_paper=61)
    assert t7["n_pairs"] == 1
    assert t7["status"] == "done"
    assert abs(t7["evasion_rate"]["mean"] - (40 - 10) / 40) < 1e-9
    assert t6["n_engines_paper"] == 61
    assert abs(t6["detection_rate_adversarial"]["mean"] - 10 / 75) < 1e-9
    assert abs(t6["detection_rate_adversarial_paper_N61"]["mean"] - 10 / 61) < 1e-9
    assert t7["n_engines_observed"]["mean"] == 75


def test_generator_starts_with_few_added_bits():
    cfg = Config()
    cfg.n_imports = 40
    cfg.n_sections = 8
    gan = MalGAN(cfg, seed=0)
    malware = np.zeros((32, cfg.n_features), dtype=np.float32)
    malware[:, 0] = 1.0
    adv = gan.generate(malware, np.random.default_rng(0), hard=True)
    added = ((adv > 0.5) & (malware < 0.5)).sum(axis=1)
    assert float(added.mean()) < 1.0


class _AlwaysBenign:
    classes_ = [0, 1]

    def predict_proba(self, X):
        p = np.zeros((len(X), 2), dtype=np.float32)
        p[:, 0] = 1.0
        return p


def test_pool_rejects_flooded_evasions():
    cfg = Config()
    cfg.n_imports = 80
    cfg.n_sections = 20
    cfg.gan_max_added = 32
    gan = MalGAN(cfg, seed=1)
    gan.G.b[-1][:] = np.float32(8.0)
    malware = np.zeros((4, cfg.n_features), dtype=np.float32)
    pools = gan.influential_pools(
        malware, malware, _AlwaysBenign(), np.random.default_rng(1), cfg
    )
    assert pools["success_rate"] == 1.0
    assert pools["mean_added_all"] > cfg.gan_max_added
    assert pools["imports"] == []
    assert pools["sections"] == []
    assert pools["mean_added"] == 0.0


def test_vt_table6_stays_on_lab_dataset():
    root = Path(__file__).resolve().parents[1]
    sha = [f"{i:064x}" for i in range(100)]
    picked, note = select_eval_hashes(sha, 500, 50)
    assert len(picked) == 50
    assert picked[0] == sha[0]
    assert "meta eval_n=50" in note
    smoke, _ = select_eval_hashes(sha, 5, 50)
    assert len(smoke) == 5
    data_dir, out = vt_job_paths(root, "data/lab_dataset")
    assert data_dir == root / "data" / "lab_dataset"
    assert out == root / "results" / "lab_dataset"
    ember = root / "results" / "vt_original_reports.jsonl"
    assert (out / "vt_original_reports.jsonl") != ember
    try:
        vt_job_paths(root, "data/paper25k")
    except ValueError:
        return
    raise AssertionError("paper25k must be refused")


def test_sha_list_accepts_numpy_column():
    hashes = np.array(["ab" * 32, "cd" * 32], dtype="U64")
    assert sha_list(hashes) == ["ab" * 32, "cd" * 32]
    assert sha_list(None) == []
    assert sha_list(np.array([], dtype="U64")) == []


def test_pe_split_matches_lab_counts():
    test_idx, train_idx, train_perm = pe_split(2500, 100, 100, 42)
    assert len(test_idx) == 100
    assert len(train_idx) == 2400
    assert len(train_perm) == 2500
    assert len(set(test_idx.tolist()) & set(train_idx.tolist())) == 0


def test_lab_scale_rejects_ember_standin():
    cfg = Config()
    y_train = np.array([1] * 24000 + [0] * 10000)
    y_test = np.ones(1000, dtype=int)
    try:
        assert_lab_scale(cfg, y_train, y_test)
    except RuntimeError as exc:
        assert "2500 malware" in str(exc)
    else:
        raise AssertionError("ember stand-in was accepted")
    old_train = np.array([1] * 24 + [0] * 10)
    old_test = np.ones(1, dtype=int)
    try:
        assert_lab_scale(cfg, old_train, old_test)
    except RuntimeError:
        pass
    else:
        raise AssertionError("25+10 corpus was accepted")
    ok_train = np.array([1] * 2400 + [0] * 1000)
    ok_test = np.ones(100, dtype=int)
    assert_lab_scale(cfg, ok_train, ok_test)


def test_edit_session_survives_a_dead_child():
    import tempfile

    from if_malevade.pe_mutate import EditSession

    src = Path(__file__).resolve().parents[1] / "data" / "cuckoo" / "smoke" / "where.exe"
    if not src.is_file():
        return
    session = EditSession()
    try:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            first = session.apply(src, "insert_section", work, section_name=".ifmnew")
            assert first.is_file()
            assert session.proc is not None
            session.proc.kill()
            session.proc.wait(timeout=5)
            second = session.apply(src, "section_append", work)
            assert second.is_file()
            assert second.stat().st_size >= src.stat().st_size
            assert session.crashes == 0
    finally:
        session.close()


def test_chained_edit_names_stay_under_max_path():
    import tempfile

    from if_malevade.pe_mutate import _out_path

    sha = "a" * 64
    tags = ["upx", "append", "addimp", "rensec", "addsec", "unused", "upxun"]
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        src = work / f"{sha}.exe"
        src.write_bytes(b"MZ")
        for i in range(50):
            nxt = _out_path(src, work, tags[i % len(tags)])
            assert nxt.resolve() != src.resolve()
            assert nxt.name.startswith(sha + ".")
            assert len(str(nxt)) < 200
            nxt.write_bytes(b"MZ")
            src = nxt


def test_table3_edits_survive_reparse():
    """insert_import / insert_section / rename_section must change the bits pefile reads."""
    import tempfile

    from if_malevade.data import pe_names, vectorize_pe
    from if_malevade.pe_mutate import apply_action

    src = Path(__file__).resolve().parents[1] / "data" / "cuckoo" / "smoke" / "where.exe"
    if not src.is_file():
        return
    imports, sections = pe_names(src)
    extra_imp = "kernel32.dll!GetTickCount"
    extra_sec = ".ifmnew"
    if extra_imp in imports:
        extra_imp = "wininet.dll!InternetOpenA"
    vocab = {"imports": list(imports) + [extra_imp], "sections": list(sections) + [extra_sec]}
    cfg = Config()
    cfg.n_imports = len(vocab["imports"])
    cfg.n_sections = len(vocab["sections"])
    base = vectorize_pe(src, vocab, cfg)
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        edited = apply_action(src, "insert_import", work, import_name=extra_imp)
        got = vectorize_pe(edited, vocab, cfg)
        assert got[len(imports)] == 1.0
        assert np.all(got[: len(imports)] >= base[: len(imports)] - 1e-6)
        assert float(got.sum() - base.sum()) == 1.0

        edited = apply_action(src, "insert_section", work, section_name=extra_sec)
        got = vectorize_pe(edited, vocab, cfg)
        assert got[cfg.n_imports + len(sections)] == 1.0

        old = sections[0]
        edited = apply_action(
            src, "rename_section", work, section_name=extra_sec, old_section=old
        )
        got = vectorize_pe(edited, vocab, cfg)
        assert got[cfg.n_imports + sections.index(old)] == 0.0
        assert got[cfg.n_imports + len(sections)] == 1.0


if __name__ == "__main__":
    test_feature_dim_is_paper_3523()
    test_reward_turn1_is_20()
    test_reward_stays_positive()
    test_or_never_drops_original_ones()
    test_edit_session_survives_a_dead_child()
    test_chained_edit_names_stay_under_max_path()
    test_table3_edits_survive_reparse()
    test_cuckoo_signature_recall()
    test_cuckoo3_submit_and_signature_gate()
    test_vt_eq3_engine_counts()
    test_generator_starts_with_few_added_bits()
    test_pool_rejects_flooded_evasions()
    test_vt_table6_stays_on_lab_dataset()
    test_sha_list_accepts_numpy_column()
    test_pe_split_matches_lab_counts()
    test_lab_scale_rejects_ember_standin()
    print("ok")
