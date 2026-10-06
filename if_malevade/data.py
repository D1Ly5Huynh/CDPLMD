"""Paper §IV.B feature space: 3269 import bits + 254 section-name bits = 3523."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import numpy as np

from .config import Config

N_IMPORTS = 3269
N_SECTIONS = 254
N_MALWARE = 25_000
N_BENIGN = 10_000
N_TEST_MALWARE = 1_000


def split_malware(X: np.ndarray, y: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    return X[y == 1], X[y == 0]


def load_paper_dataset(root: Path) -> dict:
    path = root / "data" / "paper25k" / "dataset.npz"
    if not path.exists():
        raise FileNotFoundError(
            f"missing {path}; rebuild from malware_raw.jsonl + benign_raw.jsonl"
        )
    z = np.load(path)
    n_imp = int(z["n_imports"]) if "n_imports" in z.files else N_IMPORTS
    n_sec = int(z["n_sections"]) if "n_sections" in z.files else N_SECTIONS
    xtr = z["X_train"]
    d = int(xtr.shape[1])
    paper_d = n_imp + n_sec
    if d != paper_d:
        raise RuntimeError(
            f"{path} has {d} features; paper is {n_imp}+{n_sec}={paper_d}. Rebuild npz."
        )
    sha = z["sha256_test"] if "sha256_test" in z.files else np.array([], dtype="U64")
    return {
        "X_train": xtr,
        "y_train": z["y_train"],
        "X_test": z["X_test"],
        "y_test": z["y_test"],
        "sha256_test": sha,
        "source": "paper25k",
        "n_imports": n_imp,
        "n_sections": n_sec,
    }


def _load_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def write_paper_dataset(
    mal_path: Path,
    ben_path: Path,
    out_dir: Path,
    seed: int = 42,
) -> dict:
    """Vectorize jsonl to 3523-d bits. Table 2: train malware+benign, test 1000 malware."""
    mal = _load_jsonl(mal_path)
    ben = _load_jsonl(ben_path)
    if len(mal) < N_TEST_MALWARE or len(ben) < 500:
        raise RuntimeError(f"not enough rows mal={len(mal)} ben={len(ben)}")

    imp_c: Counter[str] = Counter()
    sec_c: Counter[str] = Counter()
    for rec in mal + ben:
        imp_c.update(rec.get("imports") or [])
        sec_c.update(rec.get("sections") or [])
    imports = [k for k, _ in imp_c.most_common(N_IMPORTS)]
    sections = [k for k, _ in sec_c.most_common(N_SECTIONS)]
    imp_i = {k: i for i, k in enumerate(imports)}
    sec_i = {k: i for i, k in enumerate(sections)}
    d = N_IMPORTS + N_SECTIONS

    def row_vec(rec: dict) -> np.ndarray:
        x = np.zeros(d, dtype=np.float32)
        for name in rec.get("imports") or []:
            j = imp_i.get(name)
            if j is not None:
                x[j] = 1.0
        for name in rec.get("sections") or []:
            j = sec_i.get(name)
            if j is not None:
                x[N_IMPORTS + j] = 1.0
        return x

    mal_n = min(N_MALWARE, len(mal))
    ben_n = min(N_BENIGN, len(ben))
    X_mal = np.stack([row_vec(rec) for rec in mal[:mal_n]])
    y_mal = np.ones(mal_n, dtype=np.int32)
    X_ben = np.stack([row_vec(rec) for rec in ben[:ben_n]])
    y_ben = np.zeros(ben_n, dtype=np.int32)

    rng = np.random.default_rng(seed)
    mal_perm = rng.permutation(mal_n)
    n_test = min(N_TEST_MALWARE, mal_n)
    test_idx = mal_perm[:n_test]
    train_idx = mal_perm[n_test:]
    X_train = np.vstack([X_mal[train_idx], X_ben])
    y_train = np.concatenate([y_mal[train_idx], y_ben])
    train_perm = rng.permutation(len(y_train))
    X_train, y_train = X_train[train_perm], y_train[train_perm]
    X_test = X_mal[test_idx]
    y_test = y_mal[test_idx]
    sha_mal = np.array(
        [str(rec.get("sha256") or "") for rec in mal[:mal_n]], dtype="U64"
    )
    sha256_test = sha_mal[test_idx]

    out_dir.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(
        out_dir / "dataset.npz",
        X_train=X_train,
        y_train=y_train,
        X_test=X_test,
        y_test=y_test,
        sha256_test=sha256_test,
        n_imports=np.int32(N_IMPORTS),
        n_sections=np.int32(N_SECTIONS),
    )
    vocab = {
        "imports": imports,
        "sections": sections,
        "n_imports": N_IMPORTS,
        "n_sections": N_SECTIONS,
    }
    (out_dir / "vocab.json").write_text(json.dumps(vocab), encoding="utf-8")

    fam_path = out_dir / "paper_families.json"
    ransom_f: set[str] = set()
    backdoor_f: set[str] = set()
    if fam_path.exists():
        obj = json.loads(fam_path.read_text(encoding="utf-8"))
        ransom_f = {str(x).lower() for x in obj.get("ransomware") or []}
        backdoor_f = {str(x).lower() for x in obj.get("backdoor_rat") or []}

    def _family_bucket(avclass: str) -> int:
        s = (avclass or "").lower().strip()
        if not s:
            return 3
        if s in ransom_f or any(
            k in s
            for k in (
                "ransom",
                "crypt",
                "locker",
                "wannacry",
                "locky",
                "cerber",
                "gandcrab",
                "petya",
            )
        ):
            return 0
        if s in backdoor_f or "backdoor" in s:
            return 1
        return 3

    fam = Counter(_family_bucket(x.get("avclass", "")) for x in mal[:mal_n])
    meta = {
        "n_malware": int(mal_n),
        "n_benign": int(ben_n),
        "n_features": int(d),
        "paper": "25K malware + 10K benign Windows PE (IF-MalEvade §IV.B Table 2)",
        "split": (
            f"train {int(len(train_idx))} malware + {ben_n} benign; "
            f"test {n_test} malware / 0 benign (Table 2 test row). "
            "Held-out 1000 of the 25000 because the dump is 25k total."
        ),
        "malware_source": (
            "EMBER 2018 labeled malware PE features (imports+sections); "
            "families backdoor/ransomware as in paper §IV.B"
        ),
        "malware_filter": "avclass ransomware + backdoor/RAT",
        "n_ransomware": int(fam.get(0, 0)),
        "n_backdoor_rat": int(fam.get(1, 0)),
        "benign_source": "local Windows PE (System32/SysWOW64/Program Files)",
        "n_train": int(len(y_train)),
        "n_test": int(len(y_test)),
        "n_train_malware": int(len(train_idx)),
        "n_train_benign": int(ben_n),
        "n_test_malware": int(n_test),
        "n_test_benign": 0,
    }
    (out_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta


def apply_cfg_dims(cfg: Config, data: dict) -> Config:
    cfg.n_imports = int(data["n_imports"])
    cfg.n_sections = int(data["n_sections"])
    cfg.n_malware = int((data["y_train"] == 1).sum() + (data["y_test"] == 1).sum())
    cfg.n_benign = int((data["y_train"] == 0).sum() + (data["y_test"] == 0).sum())
    return cfg
