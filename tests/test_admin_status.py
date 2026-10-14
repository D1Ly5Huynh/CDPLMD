"""Admin dashboard reads lab JSON and does not invent a finished Cuckoo gate."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from admin.status import build_dashboard


def test_dashboard_maps_real_dike_run():
    body = build_dashboard(ROOT)
    assert body["corpus"]["eval_n"] == 50
    assert body["corpus"]["n_features"] == 3523
    assert body["corpus"]["n_sections"] == 254
    assert body["corpus"]["n_sections_observed"] == 206
    assert body["corpus"]["n_sections_padded"] == 48
    assert body["corpus"]["n_benign"] == 1000
    assert len(body["cuckoo"]["pairs"]) == 50
    assert body["cuckoo"]["pairs"][0]["match"] is True
    assert body["cuckoo"]["n_match"] == 3
    assert body["cuckoo"]["n_pending"] == 43
    assert body["cuckoo"]["next_index"] == 7
    assert "pair-index 7" in body["cuckoo"]["next_command"]
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
    assert body["virustotal"]["evasion"]["mean"] < 0.2
    assert body["baselines"]["malfoax"] in {"chua_chay", "done"}
    assert body["baselines"]["mab"] in {"chua_chay", "done"}
    rf = next(row for row in body["detectors"] if row["key"] == "RandomForest")
    assert rf["lab"]["adr"] == 1.0
    assert rf["paper"]["adr"] == 0.091


def test_missing_pair_file_stays_pending(tmp_path=None):
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        data = root / "data" / "dike2500"
        results = root / "results" / "dike2500"
        data.mkdir(parents=True)
        results.mkdir(parents=True)
        (data / "meta.json").write_text(json.dumps({"eval_n": 2, "n_features": 3}), encoding="utf-8")
        body = build_dashboard(root)
        assert body["cuckoo"]["pairs"] == []
        assert body["cuckoo"]["n_match"] == 0


if __name__ == "__main__":
    test_dashboard_maps_real_dike_run()
    test_missing_pair_file_stays_pending()
    print("ok")
