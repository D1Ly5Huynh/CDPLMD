"""Read-only lab status for the admin UI, mapped to IF-MalEvade sections.

Does not submit files, call VirusTotal, or read PE bytes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# Published Table 4–7 cells (Arif et al., IEEE Access 2023). Fractions, not lab reruns.
PAPER = {
    "n_malware": 25000,
    "n_benign": 10000,
    "n_test_malware": 1000,
    "eval_n": 500,
    "n_features": 3523,
    "n_imports": 3269,
    "n_sections": 254,
    "family": "VirusShare backdoor + ransomware",
    "detectors": {
        "RandomForest": {"auc": 0.9612, "odr": 0.9232, "adr": 0.091, "adr_after": 0.579},
        "GradientBoosting": {"auc": 0.9585, "odr": 0.9524, "adr": 0.1356, "adr_after": 0.481},
        "MLP": {"auc": 0.8650, "odr": 0.8452, "adr": 0.0769, "adr_after": 0.498},
        "DecisionTree": {"auc": 0.9656, "odr": 0.9298, "adr": 0.081, "adr_after": 0.546},
    },
    "table6_original": {"min": 0.618, "mean": 0.618, "max": 0.851, "min_published": 0.272},
    "table6_ifm": {"min": 0.154, "mean": 0.218, "max": 0.355},
    "table7_ifm": {"min": 0.157, "mean": 0.578, "max": 0.755},
    "table6_malfoax": {"mean": 0.302},
    "table6_mab": {"mean": 0.429},
    "table7_malfoax": {"mean": 0.382},
    "table7_mab": {"mean": 0.192},
}

DETECTOR_LABEL = {
    "RandomForest": "Random Forest",
    "GradientBoosting": "Gradient Boosting",
    "MLP": "MLP",
    "DecisionTree": "Decision Tree",
}

ACTIONS = [
    ("insert_import", "Thêm một import từ pool GAN"),
    ("insert_section", "Thêm một section từ pool GAN"),
    ("rename_section", "Đổi tên section: tắt tên cũ, bật tên pool"),
    ("section_append", "Ghi byte vào vùng không execute"),
    ("upx_pack", "Nén UPX"),
    ("upx_unpack", "Giải nén UPX"),
    ("overly_append", "Append overlay cuối file"),
]


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        body = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return body if isinstance(body, dict) else None


def _pct(value: object) -> str:
    if not isinstance(value, (int, float)):
        return "—"
    return f"{float(value) * 100:.1f}%"


def _span(block: dict | None, key: str) -> dict[str, float] | None:
    if not isinstance(block, dict):
        return None
    raw = block.get(key)
    if not isinstance(raw, dict):
        return None
    out: dict[str, float] = {}
    for name in ("min", "mean", "max"):
        if name in raw:
            out[name] = float(raw[name])
    return out or None


def _baseline_vt_bit(label: str, row: dict, vt: dict) -> str:
    det = vt.get("detection_rate") if isinstance(vt.get("detection_rate"), dict) else {}
    ev = vt.get("evasion_rate") if isinstance(vt.get("evasion_rate"), dict) else {}
    n = int(vt.get("n_pairs") or 0)
    target = int(vt.get("n_target") or 0)
    count = f"{n}/{target}" if target else str(n)
    local = _pct(row.get("evade"))
    if isinstance(det.get("mean"), (int, float)) and isinstance(ev.get("mean"), (int, float)):
        return (
            f"{label} VT phát hiện {_pct(det.get('mean'))}, evasion {_pct(ev.get('mean'))} ({count}). "
            f"Né GB {local}."
        )
    return f"{label} VT {vt.get('status') or 'chua_chay'} {count}. Né GB {local}."


def _baseline_lab_line(mab_row: dict, fox_row: dict, mab_vt: dict, fox_vt: dict) -> str:
    if not mab_row and not fox_row:
        return "Chưa chạy trên bộ lab."
    return _baseline_vt_bit("MAB", mab_row, mab_vt) + " " + _baseline_vt_bit("MalFox", fox_row, fox_vt)


def _baseline_note(mab_vt: dict, fox_vt: dict) -> str:
    if mab_vt.get("status") == "done" and fox_vt.get("status") == "done":
        return "Cột VirusTotal của MalFox và MAB đã đủ cặp. Cùng báo cáo gốc với IF-MalEvade."
    return "Detector cục bộ đã có. Cột VirusTotal của MalFox và MAB chưa đủ cặp."


def eval_hashes(root: Path, limit: int) -> list[str]:
    npz = root / "data" / "dike2500" / "dataset.npz"
    if not npz.is_file():
        return []
    import numpy as np

    with np.load(npz, allow_pickle=True) as data:
        if "sha256_test" not in data.files:
            return []
        column = data["sha256_test"]
    hashes = [str(item) for item in column if str(item)]
    return hashes[:limit]


def _pair_row(index: int, sha: str, path: Path) -> dict[str, Any]:
    body = _read_json(path) if path.is_file() else None
    prefix = sha[:12] if sha else ""
    if not body:
        return {
            "index": index,
            "sha256": sha,
            "sha_prefix": prefix,
            "state": "pending",
            "match": None,
            "orig_state": None,
            "adv_state": None,
            "n_signatures": 0,
            "orig_signatures": [],
            "adv_signatures": [],
            "orig_analysis_id": None,
            "adv_analysis_id": None,
        }
    orig_names = [str(x) for x in body.get("orig_signatures") or []]
    adv_names = [str(x) for x in body.get("adv_signatures") or []]
    return {
        "index": index,
        "sha256": sha or str(body.get("sha256") or ""),
        "sha_prefix": (sha or str(body.get("sha256") or ""))[:12],
        "state": "done",
        "match": bool(body.get("match")),
        "orig_state": body.get("orig_state"),
        "adv_state": body.get("adv_state"),
        "n_signatures": len(orig_names),
        "orig_signatures": orig_names,
        "adv_signatures": adv_names,
        "orig_analysis_id": body.get("orig_analysis_id"),
        "adv_analysis_id": body.get("adv_analysis_id"),
    }


def cuckoo_pairs(root: Path, hashes: list[str]) -> list[dict[str, Any]]:
    out_dir = root / "results" / "dike2500"
    rows = []
    if hashes:
        for index, sha in enumerate(hashes):
            rows.append(_pair_row(index, sha, out_dir / f"cuckoo_pair{index}.json"))
        return rows
    for path in sorted(out_dir.glob("cuckoo_pair*.json")):
        suffix = path.stem.removeprefix("cuckoo_pair")
        if not suffix.isdigit():
            continue
        body = _read_json(path) or {}
        rows.append(_pair_row(int(suffix), str(body.get("sha256") or ""), path))
    return rows


def _feature_lab(meta: dict, n_features: int) -> str:
    n_imp = meta.get("n_imports", 3269)
    n_sec = meta.get("n_sections", 154)
    text = f"{n_features} chiều = {n_imp} import + {n_sec} section."
    observed = meta.get("n_sections_observed")
    padded = meta.get("n_sections_padded")
    if observed is not None and padded:
        text += (
            f" {observed} tên có trong Dike, {padded} tên PE chuẩn thêm cho đủ trần paper,"
            " các cột đó toàn 0."
        )
    return text


def _stage(
    key: str,
    paper: str,
    title: str,
    state: str,
    lab: str,
    published: str,
    href: str,
) -> dict[str, str]:
    return {
        "key": key,
        "paper": paper,
        "title": title,
        "state": state,
        "lab": lab,
        "published": published,
        "href": href,
    }


def build_dashboard(root: Path) -> dict[str, Any]:
    root = Path(root)
    meta = _read_json(root / "data" / "dike2500" / "meta.json") or {}
    summary = _read_json(root / "results" / "dike2500" / "summary.json") or {}
    table6 = summary.get("table6") if isinstance(summary.get("table6"), dict) else {}
    table7 = summary.get("table7") if isinstance(summary.get("table7"), dict) else {}
    pools = _read_json(root / "results" / "dike2500" / "influential_features.json") or {}
    smoke = _read_json(root / "results" / "dike2500" / "cuckoo_smoke.json")
    cfg = summary.get("config") if isinstance(summary.get("config"), dict) else {}

    eval_n = int(meta.get("eval_n") or summary.get("n_eval") or 50)
    hashes = eval_hashes(root, eval_n)
    baselines_doc = _read_json(root / "results" / "dike2500" / "baselines.json") or {}
    mab_row = baselines_doc.get("mab") if isinstance(baselines_doc.get("mab"), dict) else {}
    fox_row = baselines_doc.get("malfox") if isinstance(baselines_doc.get("malfox"), dict) else {}
    mab_vt = mab_row.get("vt") if isinstance(mab_row.get("vt"), dict) else {}
    fox_vt = fox_row.get("vt") if isinstance(fox_row.get("vt"), dict) else {}
    pairs = cuckoo_pairs(root, hashes)
    n_match = sum(1 for row in pairs if row["match"] is True)
    n_miss = sum(1 for row in pairs if row["state"] == "done" and row["match"] is False)
    n_pending = sum(1 for row in pairs if row["state"] == "pending")
    next_index = next((row["index"] for row in pairs if row["state"] == "pending"), None)
    mutant_dir = root / "results" / "dike2500" / "mutants"
    n_mutants = len(list(mutant_dir.glob("*.mut.exe"))) if mutant_dir.is_dir() else 0

    detectors = []
    table4 = summary.get("table4") if isinstance(summary.get("table4"), dict) else {}
    table5 = summary.get("table5") if isinstance(summary.get("table5"), dict) else {}
    for key, label in DETECTOR_LABEL.items():
        lab4 = table4.get(key) if isinstance(table4.get(key), dict) else {}
        lab5 = table5.get(key) if isinstance(table5.get(key), dict) else {}
        published = PAPER["detectors"][key]
        detectors.append(
            {
                "key": key,
                "label": label,
                "lab": {
                    "auc": lab4.get("AUC"),
                    "odr": lab4.get("ODR"),
                    "adr": lab4.get("ADR"),
                    "adr_after": lab5.get("ADR_after"),
                },
                "paper": published,
            }
        )

    gan_done = summary.get("gan_last_evade_batch") is not None
    dqn_done = summary.get("dqn_evade_last20") is not None
    tables_done = bool(table4) and bool(table5)
    vt_done = table6.get("status") == "done" and table7.get("status") == "done"
    cuckoo_state = "mot_phan" if n_match or n_miss else "chua_chay"
    if pairs and n_pending == 0 and n_miss == 0 and n_match == len(pairs):
        cuckoo_state = "xong"

    n_features = int(meta.get("n_features") or summary.get("n_features") or 0)
    stages = [
        _stage(
            "table2",
            "Table 2",
            "Dataset",
            "mot_phan",
            f"{meta.get('n_malware', 2500)} malware Dike + {meta.get('n_benign', 100)} benign. Train {meta.get('n_train_malware', 2400)}+{meta.get('n_train_benign', 100)}, test {meta.get('n_test_malware', 100)}.",
            f"{PAPER['n_malware']} malware VirusShare + {PAPER['n_benign']} benign. Test {PAPER['n_test_malware']}.",
            "#dataset",
        ),
        _stage(
            "features",
            "§IV.B",
            "Import + section",
            "mot_phan" if n_features and n_features != PAPER["n_features"] else "xong",
            _feature_lab(meta, n_features),
            f"{PAPER['n_features']} chiều = {PAPER['n_imports']} import + {PAPER['n_sections']} section.",
            "#dataset",
        ),
        _stage(
            "malgan",
            "§E",
            "MalGAN",
            "xong" if gan_done else "chua_chay",
            f"Batch cuối né {_pct(summary.get('gan_last_evade_batch'))}. Pool {pools.get('n_imports_pool', '—')} import, {pools.get('n_sections_pool', '—')} section.",
            "G hidden 256, noise d+10, 100 epoch, OR-only.",
            "#malgan",
        ),
        _stage(
            "dqn",
            "Table 3",
            "DQN + sửa PE",
            "xong" if dqn_done else "chua_chay",
            (
                f"20 episode cuối né {_pct(summary.get('dqn_evade_last20'))}. "
                f"Eval trung bình "
                f"{float(summary['mean_turns']):.0f} lượt. "
                if isinstance(summary.get("mean_turns"), (int, float))
                else f"20 episode cuối né {_pct(summary.get('dqn_evade_last20'))}. "
            )
            + f"PE bỏ qua {summary.get('pe_edits_skipped')}. Mutant trên đĩa {n_mutants}.",
            "500 episode, γ 0.98, MAXTURN 50, ε 1.0→0.05, 7 action. Paper rebuild bằng PE Bliss.",
            "#dqn",
        ),
        _stage(
            "table4",
            "Table 4",
            "Bốn detector",
            "xong" if tables_done else "chua_chay",
            "ODR/ADR/AUC trên 50 mẫu eval của lab.",
            "Paper ADR khoảng 8–14%, ODR khoảng 85–95%.",
            "#detectors",
        ),
        _stage(
            "table5",
            "Table 5",
            "Adversarial retrain",
            "xong" if tables_done else "chua_chay",
            "Retrain 50% eval. ADR sau retrain lấy từ summary.",
            "Paper ADR sau retrain khoảng 48–58%.",
            "#detectors",
        ),
        _stage(
            "table6",
            "Table 6 · Eq. (3)",
            "VirusTotal detection",
            "xong" if vt_done else "chua_chay",
            "n/N theo từng báo cáo. 50/50 hash gốc và 50 mutant.",
            "Paper: gốc mean 61.8%, IF-MalEvade 21.8%. N cố định 61.",
            "#virustotal",
        ),
        _stage(
            "table7",
            "Table 7 · Eq. (4)",
            "VirusTotal evasion",
            "xong" if vt_done else "chua_chay",
            "Evasion trên 50 cặp đã upload.",
            "Paper IF-MalEvade mean 57.8%.",
            "#virustotal",
        ),
        _stage(
            "cuckoo",
            "§IV",
            "Cổng chữ ký Cuckoo",
            cuckoo_state,
            f"Khớp {n_match}, lệch {n_miss}, chưa chạy {n_pending}. min_recall 1.0.",
            "Giữ mutant khi mọi signature của mẫu gốc còn trên mutant.",
            "#cuckoo",
        ),
        _stage(
            "baselines",
            "Table 6–7",
            "MalFox và MAB-Malware",
            "xong"
            if mab_vt.get("status") == "done" and fox_vt.get("status") == "done"
            else (
                "mot_phan"
                if mab_row.get("status") == "done" or fox_row.get("status") == "done"
                else "chua_chay"
            ),
            _baseline_lab_line(mab_row, fox_row, mab_vt, fox_vt),
            "Paper so cùng tập 500 mẫu trên VirusTotal. Lab upload mutant baseline, giữ nguyên cột IF-MalEvade.",
            "#baselines",
        ),
    ]

    return {
        "preset": summary.get("preset") or "dike2500",
        "source": summary.get("source") or "data/dike2500",
        "paper_doi": "10.1109/ACCESS.2023.3334645",
        "stages": stages,
        "corpus": {
            "n_malware": meta.get("n_malware"),
            "n_benign": meta.get("n_benign"),
            "n_train_malware": meta.get("n_train_malware"),
            "n_train_benign": meta.get("n_train_benign"),
            "n_test_malware": meta.get("n_test_malware"),
            "eval_n": eval_n,
            "n_features": n_features,
            "n_imports": meta.get("n_imports"),
            "n_sections": meta.get("n_sections"),
            "n_sections_observed": meta.get("n_sections_observed"),
            "n_sections_padded": meta.get("n_sections_padded"),
            "seed": meta.get("seed"),
            "family": "DikeDataset trojan/generic",
            "paper_family": PAPER["family"],
            "paper_n_malware": PAPER["n_malware"],
            "paper_n_benign": PAPER["n_benign"],
            "paper_eval_n": PAPER["eval_n"],
            "paper_n_features": PAPER["n_features"],
        },
        "train": {
            "gan_last_evade_batch": summary.get("gan_last_evade_batch"),
            "dqn_evade_last20": summary.get("dqn_evade_last20"),
            "mutate_evade": summary.get("mutate_evade"),
            "mean_turns": summary.get("mean_turns"),
            "pe_edits_skipped": summary.get("pe_edits_skipped"),
            "n_mutants": n_mutants,
            "n_imports_pool": pools.get("n_imports_pool"),
            "n_sections_pool": pools.get("n_sections_pool"),
            "mean_added": pools.get("mean_added"),
            "actions": [{"name": name, "note": note} for name, note in ACTIONS],
            "locked": {
                "leaky": cfg.get("leaky"),
                "dqn_h1": cfg.get("dqn_h1"),
                "dqn_h2": cfg.get("dqn_h2"),
                "gamma": cfg.get("gamma"),
                "episodes": cfg.get("episodes"),
                "max_turn": cfg.get("max_turn"),
                "dqn_lr": cfg.get("dqn_lr"),
                "epsilon_start": cfg.get("epsilon_start"),
                "epsilon_end": cfg.get("epsilon_end"),
            },
        },
        "detectors": detectors,
        "virustotal": {
            "status": "xong" if vt_done else "chua_chay",
            "n_original_ok": table6.get("n_original_ok"),
            "n_pairs": table7.get("n_pairs"),
            "original": _span(table6, "detection_rate_original"),
            "adversarial": _span(table6, "detection_rate_adversarial"),
            "evasion": _span(table7, "evasion_rate"),
            "paper_n61_original": _span(table6, "detection_rate_original_paper_N61"),
            "paper_original": {"min": 0.272, "mean": 0.618, "max": 0.851},
            "paper_ifm_detection": PAPER["table6_ifm"],
            "paper_ifm_evasion": PAPER["table7_ifm"],
            "paper_malfoax_detection": PAPER["table6_malfoax"]["mean"],
            "paper_mab_detection": PAPER["table6_mab"]["mean"],
            "paper_malfoax_evasion": PAPER["table7_malfoax"]["mean"],
            "paper_mab_evasion": PAPER["table7_mab"]["mean"],
            "note": "Số lab dùng n/N của từng báo cáo. Cột chia 61 vượt 1 vì engine thực tế nhiều hơn 61.",
        },
        "cuckoo": {
            "min_recall": 1.0,
            "n_match": n_match,
            "n_miss": n_miss,
            "n_pending": n_pending,
            "n_pairs": len(pairs),
            "next_index": next_index,
            "next_command": (
                None
                if next_index is None
                else f"python scripts/cuckoo_gate.py --pair-index {next_index} --max-wait 900"
            ),
            "smoke": None
            if not smoke
            else {
                "file": smoke.get("file"),
                "analysis_id": smoke.get("analysis_id"),
                "state": smoke.get("state"),
                "signatures": smoke.get("signatures") or [],
            },
            "pairs": pairs,
        },
        "baselines": {
            "malfoax": fox_row.get("status") or "chua_chay",
            "mab": mab_row.get("status") or "chua_chay",
            "mab_evade": mab_row.get("evade"),
            "malfox_evade": fox_row.get("evade"),
            "mab_adr": mab_row.get("adr") or {},
            "malfox_adr": fox_row.get("adr") or {},
            "mab_vt_status": mab_vt.get("status") or "chua_chay",
            "malfox_vt_status": fox_vt.get("status") or "chua_chay",
            "mab_vt_detection": _span(mab_vt, "detection_rate"),
            "mab_vt_evasion": _span(mab_vt, "evasion_rate"),
            "malfox_vt_detection": _span(fox_vt, "detection_rate"),
            "malfox_vt_evasion": _span(fox_vt, "evasion_rate"),
            "mab_vt_pairs": mab_vt.get("n_pairs"),
            "malfox_vt_pairs": fox_vt.get("n_pairs"),
            "mab_vt_target": mab_vt.get("n_target"),
            "malfox_vt_target": fox_vt.get("n_target"),
            "note": _baseline_note(mab_vt, fox_vt),
        },
    }
