#!/usr/bin/env python3
"""Build the IF-MalEvade-sized dataset: 25k malware + 10k benign PE feature rows.

Paper (Arif et al. 2023 §IV.B): 25K malware PE (VirusShare + VirusTotal,
backdoor + ransomware) and 10K benign (clean Windows 10 system files +
known programs), screened as Windows executables.

This lab:
  * benign  = import/section vectors from local Windows PE (paper's benign source)
  * malware = 25k labeled-malicious PE records with imports/sections from
              EMBER 2018 (public PE feature dump; no malware binaries)

Does not download VirusShare/VirusTotal/MalwareBazaar binaries.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tarfile
from collections import Counter
from pathlib import Path

import numpy as np
import requests
from tqdm import tqdm

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "paper25k"
EMBER_2018 = "https://ember.elastic.co/ember_dataset_2018_2.tar.bz2"
EMBER_2017 = "https://ember.elastic.co/ember_dataset.tar.bz2"
N_MAL = 25_000
N_BEN = 10_000
N_IMPORTS = 3269
N_SECTIONS = 254
RANSOM_KEYS = (
    "ransom",
    "crypt",
    "locker",
    "wannacry",
    "locky",
    "cerber",
    "gandcrab",
    "virlock",
    "petya",
    "tesla",
    "crypren",
    "filecoder",
)
BACKDOOR_KEYS = (
    "backdoor",
    "xtrat",
    "bladabindi",
    "nanocore",
    "sdbot",
    "darkkomet",
    "darkcomet",
    "poison",
    "remcos",
    "hupigon",
    "farfli",
    "ircbot",
    "wabot",
    "njrat",
    "nanobot",
    "spygate",
    "rebhip",
    "rbot",
    "plugx",
    "zegost",
    "bifrose",
    "cybergate",
    "netwire",
    "adwind",
)

BENIGN_ROOTS = [
    Path(r"C:\Windows\System32"),
    Path(r"C:\Windows\SysWOW64"),
    Path(r"C:\Program Files"),
    Path(r"C:\Program Files (x86)"),
]
PE_EXT = {".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr"}


def _norm_imp(dll: str, fn: str) -> str:
    return f"{dll.lower()}!{fn}"


def _load_family_sets() -> tuple[set[str], set[str]]:
    path = OUT / "paper_families.json"
    ransom: set[str] = set()
    backdoor: set[str] = set()
    if path.exists():
        obj = json.loads(path.read_text(encoding="utf-8"))
        ransom = {str(x).lower() for x in obj.get("ransomware") or []}
        backdoor = {str(x).lower() for x in obj.get("backdoor_rat") or []}
    return ransom, backdoor


_RANSOM_FAMILIES, _BACKDOOR_FAMILIES = set(), set()


def _family_priority(avclass: str) -> int:
    """0=ransomware, 1=backdoor/RAT (paper §IV.B), 3=other."""
    s = (avclass or "").lower().strip()
    if not s:
        return 3
    if s in _RANSOM_FAMILIES or any(k in s for k in RANSOM_KEYS):
        return 0
    if s in _BACKDOOR_FAMILIES or any(k in s for k in BACKDOOR_KEYS):
        return 1
    return 3


def extract_ember_row(obj: dict) -> dict | None:
    imps_obj = obj.get("imports") or {}
    imports: list[str] = []
    for dll, fns in imps_obj.items():
        dll_s = str(dll)
        for fn in fns or []:
            if fn:
                imports.append(_norm_imp(dll_s, str(fn)[:256]))
    sections = []
    for s in (obj.get("section") or {}).get("sections") or []:
        name = str(s.get("name") or "").strip("\x00").strip()
        if name:
            sections.append(name[:32])
    if not imports and not sections:
        return None
    return {
        "sha256": obj.get("sha256"),
        "avclass": obj.get("avclass") or "",
        "imports": imports,
        "sections": sections,
        "packed": int(any("upx" in x.lower() for x in sections)),
    }


def _paper_class_count(buckets: dict[int, list[dict]]) -> int:
    return len(buckets[0]) + len(buckets[1])


def fetch_ember_malware(dest: Path, n: int, url: str) -> int:
    dest.parent.mkdir(parents=True, exist_ok=True)
    global _RANSOM_FAMILIES, _BACKDOOR_FAMILIES
    _RANSOM_FAMILIES, _BACKDOOR_FAMILIES = _load_family_sets()

    seen: set[str] = set()
    buckets: dict[int, list[dict]] = {0: [], 1: [], 2: [], 3: []}
    if dest.exists():
        with dest.open(encoding="utf-8") as f:
            for line in f:
                rec = json.loads(line)
                prio = _family_priority(rec.get("avclass", ""))
                if prio > 1:
                    continue
                sha = rec.get("sha256") or ""
                if not sha or sha in seen:
                    continue
                seen.add(sha)
                buckets[prio].append(rec)
        print(
            "cached paper-class rows:",
            _paper_class_count(buckets),
            "(0=ransom",
            len(buckets[0]),
            "1=backdoor/RAT",
            len(buckets[1]),
            ")",
        )
        if _paper_class_count(buckets) >= n:
            ordered = (buckets[0] + buckets[1])[:n]
            with dest.open("w", encoding="utf-8") as f:
                for rec in ordered:
                    f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            print(f"malware jsonl already has {len(ordered)} paper-class rows")
            return len(ordered)

    print(f"streaming {url} until {n} backdoor/ransomware rows")
    r = requests.get(url, stream=True, timeout=60)
    r.raise_for_status()
    total = int(r.headers.get("Content-Length") or 0)
    r.raw.decode_content = False
    done = False
    bar = tqdm(total=total or None, unit="B", unit_scale=True, desc="EMBER")
    try:
        with tarfile.open(fileobj=_ProgressReader(r.raw, bar), mode="r|bz2") as tar:
            for member in tar:
                if not member.isfile() or not member.name.endswith(".jsonl"):
                    continue
                if "train" not in member.name and "test" not in member.name:
                    continue
                fh = tar.extractfile(member)
                if fh is None:
                    continue
                for raw in fh:
                    try:
                        obj = json.loads(raw)
                    except json.JSONDecodeError:
                        continue
                    if int(obj.get("label", -1)) != 1:
                        continue
                    prio = _family_priority(str(obj.get("avclass") or ""))
                    if prio > 1:
                        continue
                    row = extract_ember_row(obj)
                    if row is None:
                        continue
                    sha = row["sha256"] or hashlib.sha1(raw[:200]).hexdigest()
                    if sha in seen:
                        continue
                    seen.add(sha)
                    row["sha256"] = sha
                    buckets[prio].append(row)
                    if _paper_class_count(buckets) >= n:
                        done = True
                        break
                if done:
                    break
    finally:
        bar.close()
        r.close()

    ordered = (buckets[0] + buckets[1])[:n]
    with dest.open("w", encoding="utf-8") as f:
        for rec in ordered:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(f"wrote {len(ordered)} malware rows -> {dest}")
    fam = Counter(_family_priority(x.get("avclass", "")) for x in ordered)
    print("priority buckets (0=ransom, 1=backdoor/RAT):", dict(fam))
    top = Counter((x.get("avclass") or "(empty)") for x in ordered).most_common(12)
    print("top avclass:", top)
    return len(ordered)


class _ProgressReader:
    def __init__(self, raw, bar) -> None:
        self.raw = raw
        self.bar = bar

    def read(self, n: int = -1) -> bytes:
        chunk = self.raw.read(n)
        if chunk:
            self.bar.update(len(chunk))
        return chunk


def collect_windows_benign(dest: Path, n: int) -> int:
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        import pefile
    except ImportError:
        raise SystemExit("pip install pefile")

    rows: list[dict] = []
    seen_hash: set[str] = set()
    files: list[Path] = []
    for root in BENIGN_ROOTS:
        if not root.exists():
            continue
        for p in root.rglob("*"):
            if p.is_file() and p.suffix.lower() in PE_EXT:
                files.append(p)
            if len(files) >= n * 4:
                break
        if len(files) >= n * 4:
            break

    for path in tqdm(files, desc="benign PE"):
        if len(rows) >= n:
            break
        try:
            data = path.read_bytes()[:2]
            if data != b"MZ":
                continue
            digest = hashlib.sha256(path.read_bytes()[: 1024 * 1024]).hexdigest()
            if digest in seen_hash:
                continue
            pe = pefile.PE(str(path), fast_load=True)
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
            )
            imports: list[str] = []
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = (entry.dll or b"").decode("utf-8", "ignore")
                    for imp in entry.imports:
                        if imp.name:
                            imports.append(
                                _norm_imp(dll, imp.name.decode("utf-8", "ignore"))
                            )
            sections = [
                (s.Name.decode("utf-8", "ignore").strip("\x00")) for s in pe.sections
            ]
            pe.close()
            if not imports and not sections:
                continue
            seen_hash.add(digest)
            rows.append(
                {
                    "sha256": digest,
                    "path": str(path),
                    "imports": imports,
                    "sections": sections,
                    "packed": int(any("upx" in x.lower() for x in sections)),
                }
            )
        except Exception:
            continue

    with dest.open("w", encoding="utf-8") as f:
        for rec in rows:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(f"wrote {len(rows)} benign rows -> {dest}")
    return len(rows)


def _load_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            rows.append(json.loads(line))
    return rows


def vectorize(mal_path: Path, ben_path: Path, out_dir: Path) -> None:
    sys.path.insert(0, str(ROOT))
    from if_malevade.data import write_paper_dataset

    meta = write_paper_dataset(mal_path, ben_path, out_dir)
    print("saved", out_dir / "dataset.npz", meta)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--skip-malware", action="store_true")
    p.add_argument("--skip-benign", action="store_true")
    p.add_argument("--malware-url", default=EMBER_2018)
    args = p.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    global _RANSOM_FAMILIES, _BACKDOOR_FAMILIES
    _RANSOM_FAMILIES, _BACKDOOR_FAMILIES = _load_family_sets()
    mal_path = OUT / "malware_raw.jsonl"
    ben_path = OUT / "benign_raw.jsonl"
    if not args.skip_benign:
        collect_windows_benign(ben_path, N_BEN)
    if not args.skip_malware:
        try:
            fetch_ember_malware(mal_path, N_MAL, args.malware_url)
        except Exception as e:
            print("EMBER 2018 failed:", e)
            if args.malware_url == EMBER_2018:
                print("retry EMBER 2017")
                fetch_ember_malware(mal_path, N_MAL, EMBER_2017)
            else:
                raise
    if mal_path.exists() and ben_path.exists():
        vectorize(mal_path, ben_path, OUT)
    else:
        print("skip vectorize; missing jsonl")
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
    raise SystemExit(main())
