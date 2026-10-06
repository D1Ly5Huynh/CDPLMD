#!/usr/bin/env python3
"""Collect IF-MalEvade §IV.B malware from the paper's sources.

Paper: 25K Windows PE malware from VirusShare + VirusTotal
(backdoor and ransomware) and 10K benign from a clean Windows 10
system (+ known programs), screened as Windows executables.

This lab never downloads or unpacks live malware PE / VirusShare zips.
It takes:

  1. VirusShare public MD5 lists (https://virusshare.com/hashfiles/)
  2. MalDICT behavior tags = VirusShare chunks 0-465 labeled from
     ~40M VirusTotal reports via ClarAVy (ransomware / backdoor)
  3. Import + section vectors for those hashes from EMBER raw JSON
     (VirusTotal-side static PE features; no binary)
  4. Benign PE already extracted from this Windows host (paper source)

Writes data/paper25k/{malware_raw.jsonl,dataset.npz,meta.json}.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tarfile
from collections import Counter
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
from tqdm import tqdm
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "paper25k"
SRC = ROOT / "data" / "sources"
MALDICT_DIR = SRC / "maldict"
VS_DIR = SRC / "virusshare"
EMBER_DIR = SRC / "ember"
EMBER_2018 = "https://ember.elastic.co/ember_dataset_2018_2.tar.bz2"
EMBER_2017_V1 = "https://ember.elastic.co/ember_dataset.tar.bz2"
EMBER_2017 = "https://ember.elastic.co/ember_dataset_2017_2.tar.bz2"
EMBER_2018_SIZE = 1_696_539_273
EMBER_2017_V1_SIZE = 1_673_963_887
EMBER_2017_SIZE = 1_751_237_573
EMBER_2018_SHA256 = "b6052eb8d350a49a8d5a5396fbe7d16cf42848b86ff969b77464434cf2997812"
EMBER_2017_SHA256 = "60142493c44c11bc3fef292b216a293841283d86ff58384b5dc2d88194c87a6d"
N_MAL = 25_000
N_BEN = 10_000
N_IMPORTS = 3269
N_SECTIONS = 254
VS_MAX_PACK = 499
UA = {
    "User-Agent": "IF-MalEvade-repro academic hash/metadata collector (no binaries)"
}
MALDICT_FILES = {
    "maldict_category_train.jsonl": (
        "https://media.githubusercontent.com/media/rjjoyce/MalDICT/main/"
        "MalDICT_Tags/maldict_category_train.jsonl",
        313_116_717,
    ),
    "maldict_category_test.jsonl": (
        "https://media.githubusercontent.com/media/rjjoyce/MalDICT/main/"
        "MalDICT_Tags/maldict_category_test.jsonl",
        46_269_303,
    ),
}
RANSOM_TAGS = {"ransomware"}
BACKDOOR_TAGS = {"backdoor", "rat"}
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


def _norm_imp(dll: str, fn: str) -> str:
    return f"{dll.lower()}!{fn}"


def _family_priority(avclass: str) -> int:
    s = (avclass or "").lower().strip()
    if not s:
        return 3
    if any(k in s for k in RANSOM_KEYS):
        return 0
    if any(k in s for k in BACKDOOR_KEYS):
        return 1
    return 3


def _tag_priority(tags: list[str]) -> int:
    low = {t.lower() for t in tags}
    if low & RANSOM_TAGS or any("ransom" in t for t in low):
        return 0
    if low & BACKDOOR_TAGS or any("backdoor" in t for t in low):
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
    md5 = str(obj.get("md5") or "").lower().strip()
    sha = str(obj.get("sha256") or "").lower().strip()
    return {
        "sha256": sha,
        "md5": md5,
        "avclass": obj.get("avclass") or "",
        "imports": imports,
        "sections": sections,
        "packed": int(any("upx" in x.lower() for x in sections)),
    }


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _curl_bin() -> str:
    return shutil.which("curl.exe") or shutil.which("curl") or "curl.exe"


def download_resumable(
    url: str,
    dest: Path,
    expected: int | None = None,
    sha256: str | None = None,
) -> Path:
    """Download a large file, resuming via curl.exe (Windows Schannel / FortiGate CA)."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    def _accept(path: Path) -> None:
        if sha256:
            got = _sha256_file(path)
            if got != sha256:
                print(f"WARNING sha256 {got} != {sha256} size={path.stat().st_size}")
                if expected and path.stat().st_size != expected:
                    raise RuntimeError(f"sha256 mismatch {path}: {got} != {sha256}")

    if dest.exists() and (expected is None or dest.stat().st_size == expected):
        _accept(dest)
        print("cached", dest, dest.stat().st_size)
        return dest
    tmp = dest.with_suffix(dest.suffix + ".part")
    existing = tmp.stat().st_size if tmp.exists() else 0
    if expected and existing == expected:
        _accept(tmp)
        tmp.replace(dest)
        print("finalized partial", dest, dest.stat().st_size)
        return dest
    if existing:
        print(f"resume {dest.name} from {existing}")
    curl = _curl_bin()
    cmd = [
        curl,
        "-L",
        "--fail",
        "--retry",
        "80",
        "--retry-all-errors",
        "--retry-delay",
        "5",
        "-C",
        "-",
        "--output",
        str(tmp),
        url,
    ]
    print("curl", " ".join(cmd))
    last_err: Exception | None = None
    for attempt in range(1, 6):
        try:
            proc = subprocess.run(cmd, check=False)
            if proc.returncode != 0:
                raise IOError(f"curl exit {proc.returncode}")
            size = tmp.stat().st_size if tmp.exists() else 0
            if expected and size != expected:
                raise IOError(f"size {size} != expected {expected}")
            _accept(tmp)
            tmp.replace(dest)
            print("wrote", dest, dest.stat().st_size)
            return dest
        except (OSError, IOError, RuntimeError) as e:
            last_err = e
            existing = tmp.stat().st_size if tmp.exists() else 0
            print(f"download retry {attempt}/5 after {e} (have {existing} bytes)")
            time.sleep(min(30, 2 ** attempt))
    raise RuntimeError(f"download failed {url}: {last_err}")


def _http_get(url: str, timeout: int = 60) -> requests.Response:
    last: Exception | None = None
    for verify in (True, False):
        try:
            r = requests.get(url, timeout=timeout, headers=UA, verify=verify)
            r.raise_for_status()
            return r
        except requests.RequestException as e:
            last = e
    raise RuntimeError(f"GET failed {url}: {last}")


def _get(url: str, dest: Path, expected: int | None = None) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and dest.stat().st_size > 0:
        if expected is None or dest.stat().st_size == expected:
            print("cached", dest, dest.stat().st_size)
            return dest
    tmp = dest.with_suffix(dest.suffix + ".part")
    r = _http_get(url, timeout=180)
    total = int(r.headers.get("Content-Length") or expected or 0)
    with tmp.open("wb") as f, tqdm(
        total=total or None, unit="B", unit_scale=True, desc=dest.name
    ) as bar:
        for chunk in r.iter_content(1024 * 256):
            if chunk:
                f.write(chunk)
                bar.update(len(chunk))
    tmp.replace(dest)
    print("wrote", dest, dest.stat().st_size)
    return dest


def download_maldict() -> list[Path]:
    paths = []
    for name, (url, size) in MALDICT_FILES.items():
        paths.append(_get(url, MALDICT_DIR / name, size))
    return paths


def load_maldict_paper_md5s(paths: list[Path]) -> dict[str, dict]:
    """md5 -> {prio, tags} for ransomware/backdoor from VirusShare+VT."""
    out: dict[str, dict] = {}
    for path in paths:
        with path.open(encoding="utf-8") as f:
            for line in tqdm(f, desc=f"parse {path.name}", unit="row"):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                md5 = str(entry.get("md5") or "").lower()
                if len(md5) != 32:
                    continue
                tags = [str(rank[0]) for rank in (entry.get("ranking") or []) if rank]
                prio = _tag_priority(tags)
                if prio > 1:
                    continue
                prev = out.get(md5)
                if prev is None or prio < prev["prio"]:
                    out[md5] = {"prio": prio, "tags": tags}
    n0 = sum(1 for v in out.values() if v["prio"] == 0)
    n1 = sum(1 for v in out.values() if v["prio"] == 1)
    print(f"MalDICT paper-class md5: {len(out)} (ransomware={n0} backdoor={n1})")
    return out


def vs_url(pack: int) -> str:
    return f"https://virusshare.com/hashfiles/VirusShare_{pack:05d}.md5"


def download_one_vs(pack: int) -> Path | None:
    dest = VS_DIR / f"VirusShare_{pack:05d}.md5"
    if dest.exists() and dest.stat().st_size > 1000:
        return dest
    url = vs_url(pack)
    try:
        r = _http_get(url, timeout=60)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(r.content)
        return dest
    except Exception as e:
        print("VS pack", pack, "error", e)
        return None


def download_virusshare_packs(max_pack: int, workers: int = 8) -> list[Path]:
    VS_DIR.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    todo = list(range(max_pack + 1))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(download_one_vs, p): p for p in todo}
        for fut in tqdm(as_completed(futs), total=len(futs), desc="VirusShare hashes"):
            path = fut.result()
            if path is not None:
                paths.append(path)
    print("VirusShare hash files:", len(paths))
    return sorted(paths)


def scan_vs_hits(pack_paths: list[Path], candidates: set[str]) -> set[str]:
    hits: set[str] = set()
    if not candidates:
        return hits
    for path in tqdm(pack_paths, desc="intersect VirusShare"):
        with path.open(encoding="utf-8", errors="ignore") as f:
            for line in f:
                h = line.strip().lower()
                if len(h) == 32 and h in candidates:
                    hits.add(h)
        if len(hits) >= len(candidates):
            break
    print("VirusShare hits among candidates:", len(hits))
    return hits


def _is_primary(rec: dict) -> bool:
    src = str(rec.get("source") or "")
    return "virustotal" in src or src.startswith("maldict")


def stream_ember(
    url: str,
    maldict: dict[str, dict],
    dest_pool: Path,
    n_target: int,
) -> tuple[list[dict], list[dict]]:
    """Parse a local EMBER tarball; keep MalDICT (VirusShare+VT) hits and
    avclass ransomware/backdoor rows for a VirusShare-hash fallback.
    """
    dest_pool.parent.mkdir(parents=True, exist_ok=True)
    primary: list[dict] = []
    fallback: list[dict] = []
    seen: set[str] = set()
    if dest_pool.exists():
        with dest_pool.open(encoding="utf-8") as f:
            for line in f:
                rec = json.loads(line)
                key = rec.get("md5") or rec.get("sha256")
                if not key or key in seen:
                    continue
                seen.add(key)
                if _is_primary(rec):
                    primary.append(rec)
                else:
                    fallback.append(rec)
        print(
            "cached pool primary",
            len(primary),
            "fallback",
            len(fallback),
        )
        if len(primary) >= n_target:
            return primary[:n_target], fallback

    if "2018" in url:
        expected, digest, tar_name = EMBER_2018_SIZE, EMBER_2018_SHA256, "ember_dataset_2018_2.tar.bz2"
    elif "2017_2" in url:
        expected, digest, tar_name = EMBER_2017_SIZE, None, "ember_dataset_2017_2.tar.bz2"
    else:
        expected, digest, tar_name = EMBER_2017_V1_SIZE, None, "ember_dataset.tar.bz2"
    stamp = EMBER_DIR / f"{tar_name}.parsed"
    if stamp.exists() and dest_pool.exists() and (primary or fallback):
        print("skip parse, stamp", stamp)
        return primary, fallback
    tar_path = download_resumable(url, EMBER_DIR / tar_name, expected, digest)
    print(f"parsing {tar_path}  maldict_md5={len(maldict)}")
    wrote = 0
    with dest_pool.open("a", encoding="utf-8") as out_f:
        with tarfile.open(tar_path, mode="r|bz2") as tar:
            for member in tar:
                if not member.isfile() or not member.name.endswith(".jsonl"):
                    continue
                if "train" not in member.name and "test" not in member.name:
                    continue
                fh = tar.extractfile(member)
                if fh is None:
                    continue
                bar = tqdm(desc=Path(member.name).name, unit="row")
                stop = False
                for raw in fh:
                    bar.update(1)
                    try:
                        obj = json.loads(raw)
                    except json.JSONDecodeError:
                        continue
                    label = int(obj.get("label", -1))
                    row = extract_ember_row(obj)
                    if row is None:
                        continue
                    md5 = row["md5"]
                    sha = row["sha256"]
                    key = md5 or sha
                    if not key or key in seen:
                        continue
                    info = maldict.get(md5) if md5 else None
                    av_prio = _family_priority(row.get("avclass") or "")
                    keep = None
                    if info is not None and label != 0:
                        row["source"] = "virusshare+virustotal+ember"
                        row["maldict_tags"] = info["tags"]
                        row["prio"] = info["prio"]
                        keep = "primary"
                    elif label == 1 and av_prio <= 1 and len(fallback) < n_target * 4:
                        row["source"] = "ember_avclass_pending_virusshare"
                        row["prio"] = av_prio
                        keep = "fallback"
                    if keep is None:
                        continue
                    seen.add(key)
                    if keep == "primary":
                        primary.append(row)
                    else:
                        fallback.append(row)
                    out_f.write(json.dumps(row, ensure_ascii=False) + "\n")
                    wrote += 1
                    if wrote % 200 == 0:
                        out_f.flush()
                    if len(primary) >= n_target:
                        stop = True
                        break
                bar.close()
                if stop:
                    break
    stamp.write_text(
        json.dumps({"primary": len(primary), "fallback": len(fallback)}),
        encoding="utf-8",
    )
    print(
        "pool primary (MalDICT∩EMBER)",
        len(primary),
        "fallback avclass",
        len(fallback),
    )
    return primary, fallback


def select_25k(
    primary: list[dict],
    fallback: list[dict],
    vs_hits: set[str],
    n: int,
) -> list[dict]:
    chosen: list[dict] = []
    seen: set[str] = set()

    def take(rows: list[dict], need_vs: bool) -> None:
        ransom = [r for r in rows if int(r.get("prio", 3)) == 0]
        backdoor = [r for r in rows if int(r.get("prio", 3)) == 1]
        for rec in ransom + backdoor:
            if len(chosen) >= n:
                return
            md5 = rec.get("md5") or ""
            sha = rec.get("sha256") or ""
            key = sha or md5
            if not key or key in seen:
                continue
            if need_vs and md5 not in vs_hits:
                continue
            seen.add(key)
            if need_vs:
                rec = dict(rec)
                rec["source"] = "virusshare+ember_avclass"
            chosen.append(rec)

    take(primary, need_vs=False)
    if len(chosen) < n:
        take(fallback, need_vs=True)
    print("selected", len(chosen), "of", n)
    return chosen


def _load_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            rows.append(json.loads(line))
    return rows


def vectorize(mal: list[dict], ben_path: Path, out_dir: Path) -> None:
    tmp = out_dir / "_malware_selected.jsonl"
    with tmp.open("w", encoding="utf-8") as f:
        for rec in mal:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    sys.path.insert(0, str(ROOT))
    from if_malevade.data import write_paper_dataset

    meta = write_paper_dataset(tmp, ben_path, out_dir)
    tmp.unlink(missing_ok=True)
    print("saved", out_dir / "dataset.npz")
    print(json.dumps(meta, indent=2))


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--skip-maldict", action="store_true")
    p.add_argument("--skip-virusshare", action="store_true")
    p.add_argument("--skip-ember", action="store_true")
    p.add_argument("--vs-max-pack", type=int, default=VS_MAX_PACK)
    p.add_argument("--malware-url", default=EMBER_2018)
    args = p.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    SRC.mkdir(parents=True, exist_ok=True)

    maldict: dict[str, dict] = {}
    if not args.skip_maldict:
        paths = download_maldict()
        maldict = load_maldict_paper_md5s(paths)

    pool_path = OUT / "malware_pool.jsonl"
    primary: list[dict] = []
    fallback: list[dict] = []
    if not args.skip_ember:
        primary, fallback = stream_ember(args.malware_url, maldict, pool_path, N_MAL)
        if len(primary) < N_MAL and args.malware_url == EMBER_2018:
            v2 = EMBER_DIR / "ember_dataset_2017_2.tar.bz2"
            v2p = Path(str(v2) + ".part")
            ready = (v2.exists() and v2.stat().st_size == EMBER_2017_SIZE) or (
                v2p.exists() and v2p.stat().st_size == EMBER_2017_SIZE
            )
            if ready:
                print("EMBER 2018 primary < 25k; streaming EMBER 2017 v2")
                primary, fallback = stream_ember(EMBER_2017, maldict, pool_path, N_MAL)
            else:
                print("EMBER 2017 v2 tarball not ready yet; skip")
    else:
        if pool_path.exists():
            for rec in _load_jsonl(pool_path):
                if str(rec.get("source") or "").startswith("virusshare+virustotal"):
                    primary.append(rec)
                else:
                    fallback.append(rec)

    vs_hits: set[str] = set()
    need_vs = len(primary) < N_MAL
    if need_vs and not args.skip_virusshare:
        cand = {r["md5"] for r in fallback if r.get("md5")}
        print("need VirusShare intersection, candidates", len(cand))
        packs = download_virusshare_packs(args.vs_max_pack)
        vs_hits = scan_vs_hits(packs, cand)
    elif not args.skip_virusshare and primary:
        download_virusshare_packs(min(20, args.vs_max_pack), workers=4)

    selected = select_25k(primary, fallback, vs_hits, N_MAL)
    if len(selected) < N_MAL:
        print(
            f"WARNING: only {len(selected)} paper-source rows "
            f"(need {N_MAL}). primary={len(primary)} fallback={len(fallback)} "
            f"vs_hits={len(vs_hits)}"
        )
        print("not writing malware_raw/dataset.npz until 25000 paper-source rows")
        return 2

    mal_path = OUT / "malware_raw.jsonl"
    with mal_path.open("w", encoding="utf-8") as f:
        for rec in selected:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print("wrote", mal_path, len(selected))

    ben_path = OUT / "benign_raw.jsonl"
    if not ben_path.exists():
        raise SystemExit("missing benign_raw.jsonl — run fetch_paper_dataset.py first")
    n_ben = sum(1 for _ in ben_path.open(encoding="utf-8"))
    print("benign rows", n_ben)
    vectorize(selected, ben_path, OUT)

    readme = OUT / "README.md"
    readme.write_text(
        "\n".join(
            [
                "# Dataset — nguồn paper IF-MalEvade §IV.B",
                "",
                "- Malware: hash **VirusShare** + nhãn **VirusTotal** (MalDICT ClarAVy,",
                "  ransomware/backdoor). Vector import/section lấy từ EMBER raw của đúng hash đó.",
                "- Benign: PE Windows local (System32 / SysWOW64 / Program Files).",
                "- Không tải zip/torrent VirusShare, không unpack binary malware, không upload VT.",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return 0 if len(selected) >= N_MAL else 2


if __name__ == "__main__":
    raise SystemExit(main())
