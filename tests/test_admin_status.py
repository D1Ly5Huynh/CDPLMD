"""Admin dashboard reads lab JSON and does not invent a finished Cuckoo gate."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from admin.status import build_dashboard


def test_dashboard_points_at_lab_dataset():
    body = build_dashboard(ROOT)
    assert body["preset"] == "lab_dataset"
    assert body["source"] == "data/lab_dataset"
    assert body["corpus"]["family"] == "RanDS ransomware"
    assert body["corpus"]["eval_n"] == 50
    table2 = next(stage for stage in body["stages"] if stage["key"] == "table2")
    assert table2["state"] == "xong"
    cuckoo_stage = next(stage for stage in body["stages"] if stage["key"] == "cuckoo")
    assert cuckoo_stage["state"] == "xong"
    assert body["cuckoo"]["n_pairs"] == 50
    assert body["cuckoo"]["n_pending"] == 0
    assert body["cuckoo"]["n_miss"] > 0
    keys = [stage["key"] for stage in body["stages"]]
    assert keys == [
        "table2",
        "features",
        "malgan",
        "dqn",
        "table4",
        "table5",
        "table6",
        "table7",
        "cuckoo",
        "baselines",
    ]
    assert "dike" not in json.dumps(body).lower()
    rf = next(row for row in body["detectors"] if row["key"] == "RandomForest")
    assert rf["paper"]["adr"] == 0.091
    assert abs(rf["lab"]["auc"] - 0.997245) < 1e-9
    assert abs(rf["lab"]["adr_after"] - 0.88) < 1e-9
    vt = body["virustotal"]
    assert vt["status"] == "xong"
    assert abs(vt["original"]["mean"] - 0.7680974186868923) < 1e-12
    assert abs(vt["adversarial"]["mean"] - 0.6237333333333334) < 1e-12
    assert abs(vt["evasion"]["mean"] - 0.2045893725332635) < 1e-12


def test_missing_pair_file_stays_pending(tmp_path=None):
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        data = root / "data" / "lab_dataset"
        results = root / "results" / "lab_dataset"
        data.mkdir(parents=True)
        results.mkdir(parents=True)
        (data / "meta.json").write_text(json.dumps({"eval_n": 2, "n_features": 3}), encoding="utf-8")
        body = build_dashboard(root)
        assert body["cuckoo"]["pairs"] == []
        assert body["cuckoo"]["n_match"] == 0


if __name__ == "__main__":
    test_dashboard_points_at_lab_dataset()
    test_missing_pair_file_stays_pending()
    print("ok")
