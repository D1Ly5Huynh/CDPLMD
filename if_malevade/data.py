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


def load_paper_dataset(root: Path, dataset_dir: str | None = None) -> dict:
    rel = dataset_dir or "data/paper25k"
    path = root / rel / "dataset.npz"
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
    sha_tr = z["sha256_train"] if "sha256_train" in z.files else np.array([], dtype="U64")
    return {
        "X_train": xtr,
        "y_train": z["y_train"],
        "X_test": z["X_test"],
        "y_test": z["y_test"],
        "sha256_test": sha,
        "sha256_train": sha_tr,
        "source": rel.replace("\\", "/"),
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


def _family_sets(fam_path: Path) -> tuple[set[str], set[str]]:
    ransom_f: set[str] = set()
    backdoor_f: set[str] = set()
    if fam_path.exists():
        obj = json.loads(fam_path.read_text(encoding="utf-8"))
        ransom_f = {str(x).lower() for x in obj.get("ransomware") or []}
        backdoor_f = {str(x).lower() for x in obj.get("backdoor_rat") or []}
    return ransom_f, backdoor_f


def _family_bucket(avclass: str, ransom_f: set[str], backdoor_f: set[str]) -> int:
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


def _allocate(counts: dict[int, int], n: int) -> dict[int, int]:
    """Largest-remainder split of n across bucket sizes."""
    total = sum(counts.values())
    if total < n:
        raise RuntimeError(f"need {n} rows, buckets have {total}")
    raw = {k: n * v / total for k, v in counts.items()}
    alloc = {k: min(v, int(raw[k])) for k, v in counts.items()}
    remain = n - sum(alloc.values())
    order = sorted(counts, key=lambda k: (raw[k] - alloc[k], counts[k]), reverse=True)
    for k in order:
        if remain <= 0:
            break
        room = counts[k] - alloc[k]
        take = min(room, remain)
        alloc[k] += take
        remain -= take
    return alloc


def write_count_subset(
    mal_path: Path,
    ben_path: Path,
    vocab_path: Path,
    fam_path: Path,
    out_dir: Path,
    n_malware: int = 2500,
    n_benign: int = 100,
    n_test_malware: int | None = None,
    seed: int = 42,
) -> dict:
    """Sample a smaller 3523-d set from the paper jsonl, using the saved vocab.

    The paper feature names stay fixed. Family mix follows the source jsonl.
    Benign stays train-only, same as Table 2.
    """
    if n_malware < 2 or n_benign < 1:
        raise RuntimeError(f"need at least 2 malware and 1 benign, got {n_malware}/{n_benign}")
    n_test = n_test_malware
    if n_test is None:
        n_test = max(1, int(round(n_malware * N_TEST_MALWARE / N_MALWARE)))
    if n_test >= n_malware:
        raise RuntimeError(f"test {n_test} must be smaller than malware {n_malware}")

    vocab = json.loads(vocab_path.read_text(encoding="utf-8"))
    imports = [str(x) for x in vocab["imports"]]
    sections = [str(x) for x in vocab["sections"]]
    if len(imports) != N_IMPORTS or len(sections) != N_SECTIONS:
        raise RuntimeError(
            f"vocab is {len(imports)} imports + {len(sections)} sections, paper is {N_IMPORTS}+{N_SECTIONS}"
        )
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

    ransom_f, backdoor_f = _family_sets(fam_path)
    buckets: dict[int, list[dict]] = {0: [], 1: [], 3: []}
    for rec in _load_jsonl(mal_path):
        buckets[_family_bucket(rec.get("avclass", ""), ransom_f, backdoor_f)].append(rec)
    ben = _load_jsonl(ben_path)
    if len(ben) < n_benign:
        raise RuntimeError(f"need {n_benign} benign, got {len(ben)}")

    rng = np.random.default_rng(seed)
    alloc = _allocate({k: len(v) for k, v in buckets.items()}, n_malware)
    chosen: list[dict] = []
    for key, n_take in alloc.items():
        pool = buckets[key]
        pick = rng.choice(len(pool), size=n_take, replace=False)
        chosen.extend(pool[int(i)] for i in pick)
    order = rng.permutation(len(chosen))
    chosen = [chosen[int(i)] for i in order]
    test_recs = chosen[:n_test]
    train_mal = chosen[n_test:]
    ben_pick = rng.choice(len(ben), size=n_benign, replace=False)
    train_ben = [ben[int(i)] for i in ben_pick]

    X_train = np.vstack(
        [row_vec(rec) for rec in train_mal] + [row_vec(rec) for rec in train_ben]
    )
    y_train = np.concatenate(
        [
            np.ones(len(train_mal), dtype=np.int32),
            np.zeros(len(train_ben), dtype=np.int32),
        ]
    )
    train_perm = rng.permutation(len(y_train))
    X_train, y_train = X_train[train_perm], y_train[train_perm]
    X_test = np.vstack([row_vec(rec) for rec in test_recs])
    y_test = np.ones(len(test_recs), dtype=np.int32)
    sha256_test = np.array(
        [str(rec.get("sha256") or "") for rec in test_recs], dtype="U64"
    )

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
    (out_dir / "vocab.json").write_text(
        json.dumps(
            {
                "imports": imports,
                "sections": sections,
                "n_imports": N_IMPORTS,
                "n_sections": N_SECTIONS,
            }
        ),
        encoding="utf-8",
    )
    fam = Counter(_family_bucket(x.get("avclass", ""), ransom_f, backdoor_f) for x in chosen)
    meta = {
        "n_malware": int(n_malware),
        "n_benign": int(n_benign),
        "n_features": int(d),
        "paper": "IF-MalEvade §IV.B Table 2, subsampled for a smaller machine",
        "split": (
            f"train {len(train_mal)} malware + {n_benign} benign; "
            f"test {n_test} malware / 0 benign. "
            f"Counts requested: {n_malware} malware + {n_benign} benign "
            f"(class ratio {n_malware / n_benign:.1f}:1, not paper 2.5:1)."
        ),
        "seed": int(seed),
        "malware_source": "subsample of data/paper25k malware_raw.jsonl (EMBER import/section vectors)",
        "benign_source": "subsample of data/paper25k benign_raw.jsonl (local Windows PE)",
        "vocab": "paper25k vocab.json, not refit on the subset",
        "n_ransomware": int(fam.get(0, 0)),
        "n_backdoor_rat": int(fam.get(1, 0)),
        "n_other": int(fam.get(3, 0)),
        "n_train": int(len(y_train)),
        "n_test": int(len(y_test)),
        "n_train_malware": int(len(train_mal)),
        "n_train_benign": int(n_benign),
        "n_test_malware": int(n_test),
        "n_test_benign": 0,
        "eval_n": int(n_test // 2),
    }
    (out_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta


def write_paper_dataset(
    mal_path: Path,
    ben_path: Path,
    out_dir: Path,
    seed: int = 42,
    scale: int = 1,
) -> dict:
    """Vectorize jsonl to 3523-d bits.

    scale=1 keeps the paper-sized dump (fetch scripts).
    A uniform divisor is not required: the lab corpus is 2500 malware + 1000 benign.
    """
    mal = _load_jsonl(mal_path)
    ben = _load_jsonl(ben_path)
    n_malware = max(1, N_MALWARE // scale)
    n_benign = max(1, N_BENIGN // scale)
    n_test_malware = max(1, N_TEST_MALWARE // scale)
    if scale == 1:
        if len(mal) < N_TEST_MALWARE or len(ben) < 500:
            raise RuntimeError(f"not enough rows mal={len(mal)} ben={len(ben)}")
    elif len(mal) < n_malware or len(ben) < n_benign:
        raise RuntimeError(
            f"need {n_malware} malware + {n_benign} benign at scale {scale}, "
            f"got mal={len(mal)} ben={len(ben)}"
        )

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

    mal_n = min(n_malware, len(mal))
    ben_n = min(n_benign, len(ben))
    X_mal = np.stack([row_vec(rec) for rec in mal[:mal_n]])
    y_mal = np.ones(mal_n, dtype=np.int32)
    X_ben = np.stack([row_vec(rec) for rec in ben[:ben_n]])
    y_ben = np.zeros(ben_n, dtype=np.int32)

    rng = np.random.default_rng(seed)
    mal_perm = rng.permutation(mal_n)
    n_test = min(n_test_malware, mal_n)
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

    ransom_f, backdoor_f = _family_sets(out_dir / "paper_families.json")
    fam = Counter(
        _family_bucket(x.get("avclass", ""), ransom_f, backdoor_f) for x in mal[:mal_n]
    )
    meta = {
        "n_malware": int(mal_n),
        "n_benign": int(ben_n),
        "n_features": int(d),
        "paper": "25K malware + 10K benign Windows PE (IF-MalEvade §IV.B Table 2)",
        "split": (
            f"train {int(len(train_idx))} malware + {ben_n} benign; "
            f"test {n_test} malware / 0 benign (Table 2 test row). "
            f"scale={scale}: paper 25000/10000/test 1000 divided by scale."
        ),
        "scale": int(scale),
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


def pe_split(n_mal: int, n_ben: int, n_test: int, seed: int):
    """Table 2 split. Same seed reproduces the dike2500 row order."""
    rng = np.random.default_rng(seed)
    mal_perm = rng.permutation(n_mal)
    test_idx = mal_perm[:n_test]
    train_idx = mal_perm[n_test:]
    train_perm = rng.permutation(len(train_idx) + n_ben)
    return test_idx, train_idx, train_perm


# Standard PE section names (MSVC, CRT, packers). Each is at most 8 bytes.
# Used only to fill the paper cap of 254 when a corpus has fewer distinct
# names. ".ifmimp" stays off this list: that section is the rebuilt import
# directory and must not become a section bit.
_SECTION_FILLERS: tuple[str, ...] = (
    ".drectve",
    ".cormeta",
    ".giats",
    ".gljmp",
    ".gehcont",
    ".voltbl",
    ".00cfg",
    ".retplne",
    ".didata",
    ".sxdata",
    ".srdata",
    ".orpc",
    ".shared",
    ".debug",
    ".nep",
    ".mackt",
    ".wixburn",
    ".fptable",
    ".wpp_sf",
    ".msvcjmc",
    ".detourc",
    ".detourd",
    ".CRT$XCA",
    ".CRT$XCU",
    ".CRT$XCZ",
    ".CRT$XIA",
    ".CRT$XIU",
    ".CRT$XIZ",
    ".CRT$XLA",
    ".CRT$XLU",
    ".CRT$XLZ",
    ".CRT$XPA",
    ".CRT$XPU",
    ".CRT$XPZ",
    ".CRT$XTA",
    ".CRT$XTZ",
    ".idata$2",
    ".idata$3",
    ".idata$4",
    ".idata$5",
    ".idata$6",
    ".text$mn",
    ".text$yd",
    ".text$di",
    ".text$x",
    ".rdata$r",
    ".rdata$z",
    ".tls$",
    ".debug$S",
    ".debug$T",
    ".debug$P",
    ".debug$F",
    ".rsrc$01",
    ".rsrc$02",
    ".rsrc$03",
    ".rsrc$04",
    "UPX2",
    ".aspack",
    ".enigma1",
    ".enigma2",
    ".vmp0",
    ".vmp1",
    ".vmp2",
    ".themida",
    ".petite",
    ".nsp0",
    ".nsp1",
    ".nsp2",
    ".mpress1",
    ".mpress2",
    ".MPRESS1",
    ".MPRESS2",
    ".pec",
    ".pec1",
    ".pec2",
    ".yoda",
    ".yP",
    ".rlpack",
    ".RLPack",
    ".upack",
    ".Upack",
    ".sedata",
    ".vlizer",
    ".winlice",
    ".shrink1",
    ".shrink2",
    ".shrink3",
    ".boot",
    ".ByDwing",
    ".perplex",
    ".bind",
    "DGROUP",
    ".INIT",
    ".PAGE",
    ".BSS",
    ".DATA",
    ".text$00",
    ".text$01",
    ".data$00",
    ".reloc$",
    ".edata$",
    ".pdata$",
    ".rdata$00",
    ".rdata$01",
)


def complete_section_vocab(observed: list[str], width: int = N_SECTIONS) -> list[str]:
    """Frequency order first, then standard PE names up to the paper width.

    A corpus with fewer than 254 distinct section names still saves a
    3269+254 vector. Columns past the observed names are 0 on every row.
    """
    chosen: list[str] = []
    seen: set[str] = set()
    for name in observed:
        key = str(name)
        if key in seen:
            continue
        seen.add(key)
        chosen.append(key)
        if len(chosen) >= width:
            return chosen[:width]
    for name in _SECTION_FILLERS:
        if name in seen or len(name.encode("utf-8")) > 8:
            continue
        seen.add(name)
        chosen.append(name)
        if len(chosen) == width:
            return chosen
    raise RuntimeError(
        f"section vocabulary has {len(chosen)} names, paper width is {width}"
    )


def pe_names(path: Path) -> tuple[list[str], list[str]]:
    """Import keys ``dll!fn`` and section names, same strings as vectorize_pe."""
    import pefile

    pe = pefile.PE(str(path), fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
    )
    imports: list[str] = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = entry.dll.decode("utf-8", "ignore").lower()
        for imp in entry.imports:
            fn = imp.name.decode("utf-8", "ignore") if imp.name else f"ord{imp.ordinal}"
            imports.append(f"{dll}!{fn}")
    sections = [
        section.Name.split(b"\x00", 1)[0].decode("utf-8", "ignore")
        for section in pe.sections
    ]
    pe.close()
    return imports, sections


def write_pe_dataset(
    malware_dir: Path,
    benign_dir: Path,
    out_dir: Path,
    n_test_malware: int = 100,
    seed: int = 42,
) -> dict:
    """Binary import + section matrix from PE folders.

    Vocabulary is the most common names, capped at the paper widths
    (3269 imports, 254 section names). Fewer section names are filled to 254
    with standard PE names; those extra columns stay 0.
    Split matches Table 2: benign stays in train, malware holdout is the test.
    """
    mal_paths = sorted(p for p in malware_dir.glob("*.exe") if p.is_file())
    ben_paths = sorted(p for p in benign_dir.glob("*.exe") if p.is_file())
    if len(mal_paths) < n_test_malware + 1 or not ben_paths:
        raise RuntimeError(
            f"need malware > {n_test_malware} and at least 1 benign, "
            f"got {len(mal_paths)} + {len(ben_paths)}"
        )

    parsed: list[tuple[Path, list[str], list[str]]] = []
    for path in mal_paths + ben_paths:
        imports, sections = pe_names(path)
        parsed.append((path, sorted(set(imports)), sorted(set(sections))))

    imp_c: Counter[str] = Counter()
    sec_c: Counter[str] = Counter()
    for _, imports, sections in parsed:
        imp_c.update(imports)
        sec_c.update(sections)
    imports = [k for k, _ in imp_c.most_common(N_IMPORTS)]
    observed_sections = [k for k, _ in sec_c.most_common(N_SECTIONS)]
    sections = complete_section_vocab(observed_sections)
    n_sections_observed = len(observed_sections)
    n_sections_padded = len(sections) - n_sections_observed
    imp_i = {k: i for i, k in enumerate(imports)}
    sec_i = {k: i for i, k in enumerate(sections)}
    n_imp, n_sec = len(imports), len(sections)
    d = n_imp + n_sec

    def row_vec(imp_names: list[str], sec_names: list[str]) -> np.ndarray:
        x = np.zeros(d, dtype=np.float32)
        for name in imp_names:
            j = imp_i.get(name)
            if j is not None:
                x[j] = 1.0
        for name in sec_names:
            j = sec_i.get(name)
            if j is not None:
                x[n_imp + j] = 1.0
        return x

    n_mal = len(mal_paths)
    X_mal = np.stack([row_vec(a, b) for _, a, b in parsed[:n_mal]])
    X_ben = np.stack([row_vec(a, b) for _, a, b in parsed[n_mal:]])
    sha_mal = np.array([p.stem for p in mal_paths], dtype="U64")
    sha_ben = np.array([p.stem for p in ben_paths], dtype="U64")
    test_idx, train_idx, train_perm = pe_split(n_mal, len(ben_paths), n_test_malware, seed)
    X_train = np.vstack([X_mal[train_idx], X_ben])
    y_train = np.concatenate(
        [
            np.ones(len(train_idx), dtype=np.int32),
            np.zeros(len(ben_paths), dtype=np.int32),
        ]
    )
    sha_train = np.concatenate([sha_mal[train_idx], sha_ben])
    X_train, y_train = X_train[train_perm], y_train[train_perm]
    sha_train = sha_train[train_perm]
    X_test = X_mal[test_idx]
    y_test = np.ones(len(test_idx), dtype=np.int32)

    out_dir.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(
        out_dir / "dataset.npz",
        X_train=X_train,
        y_train=y_train,
        X_test=X_test,
        y_test=y_test,
        sha256_test=sha_mal[test_idx],
        sha256_train=sha_train,
        n_imports=np.int32(n_imp),
        n_sections=np.int32(n_sec),
    )
    vocab = {
        "imports": imports,
        "sections": sections,
        "n_imports": n_imp,
        "n_sections": n_sec,
    }
    (out_dir / "vocab.json").write_text(json.dumps(vocab), encoding="utf-8")
    meta = {
        "n_malware": int(n_mal),
        "n_benign": int(len(ben_paths)),
        "n_features": int(d),
        "n_imports": int(n_imp),
        "n_sections": int(n_sec),
        "n_sections_observed": int(n_sections_observed),
        "n_sections_padded": int(n_sections_padded),
        "paper": "IF-MalEvade §IV.B import + section bits, Table 2 split",
        "split": (
            f"train {len(train_idx)} malware + {len(ben_paths)} benign; "
            f"test {n_test_malware} malware / 0 benign"
        ),
        "seed": int(seed),
        "malware_source": "data/pe/malware DikeDataset PE",
        "benign_source": (
            "data/pe/benign: 100 DikeDataset PE plus local Windows PE to reach 1000"
        ),
        "vocab": (
            "most common imports (cap 3269). Section names observed on this "
            "corpus, then standard PE names up to the paper cap 254. "
            "Padded section columns are 0 on every row."
        ),
        "n_train": int(len(y_train)),
        "n_test": int(len(y_test)),
        "n_train_malware": int(len(train_idx)),
        "n_train_benign": int(len(ben_paths)),
        "n_test_malware": int(n_test_malware),
        "n_test_benign": 0,
        "eval_n": int(n_test_malware // 2),
    }
    (out_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta


def vectorize_pe(path: Path, vocab: dict, cfg: Config) -> np.ndarray:
    """Map a PE file onto the paper 3523-d import + section vocabulary."""
    import pefile

    pe = pefile.PE(str(path), fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
    )
    x = np.zeros(cfg.n_features, dtype=np.float32)
    imp_i = {str(k): i for i, k in enumerate(vocab.get("imports") or [])}
    sec_i = {str(k): i for i, k in enumerate(vocab.get("sections") or [])}
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = entry.dll.decode("utf-8", "ignore").lower()
        for imp in entry.imports:
            fn = imp.name.decode("utf-8", "ignore") if imp.name else f"ord{imp.ordinal}"
            j = imp_i.get(f"{dll}!{fn}")
            if j is None:
                j = imp_i.get(f"{dll}!{fn}".lower())
            if j is not None and j < cfg.n_imports:
                x[j] = 1.0
    for section in pe.sections:
        name = section.Name.split(b"\x00", 1)[0].decode("utf-8", "ignore")
        j = sec_i.get(name)
        if j is not None and j < cfg.n_sections:
            x[cfg.n_imports + j] = 1.0
    pe.close()
    return x


def apply_cfg_dims(cfg: Config, data: dict) -> Config:
    cfg.n_imports = int(data["n_imports"])
    cfg.n_sections = int(data["n_sections"])
    cfg.n_malware = int((data["y_train"] == 1).sum() + (data["y_test"] == 1).sum())
    cfg.n_benign = int((data["y_train"] == 0).sum() + (data["y_test"] == 0).sum())
    return cfg
