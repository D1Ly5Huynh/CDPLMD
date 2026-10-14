#!/usr/bin/env python3
"""Copy local Windows PE until data/pe/benign holds 1000 files.

Keeps the Dike benign files already in that folder. New files are clean
Windows executables (System32, SysWOW64, Program Files), the paper's
benign source. Does not train and does not touch data/pe/malware.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BENIGN = ROOT / "data" / "pe" / "benign"
MALWARE = ROOT / "data" / "pe" / "malware"
MANIFEST = ROOT / "data" / "pe" / "dike_manifest.json"
TARGET = 1000
MAX_BYTES = 32 * 1024 * 1024
ROOTS = (
    Path(r"C:\Windows\System32"),
    Path(r"C:\Windows\SysWOW64"),
    Path(r"C:\Program Files"),
    Path(r"C:\Program Files (x86)"),
)
SKIP_DIRS = {
    "winsxs",
    "installer",
    "servicing",
    "softwaredistribution",
    "windowsapps",
    "assembly",
    "node_modules",
    "temp",
    "cache",
    "packages",
    "catroot",
    "catroot2",
    "driverstore",
    "logs",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _usable(path: Path) -> bool:
    try:
        if not path.is_file() or path.suffix.lower() != ".exe":
            return False
        if path.stat().st_size <= 0 or path.stat().st_size > MAX_BYTES:
            return False
        with path.open("rb") as handle:
            return handle.read(2) == b"MZ"
    except OSError:
        return False


def _parses(path: Path) -> bool:
    import pefile

    pe = pefile.PE(str(path), fast_load=True)
    try:
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
        imports = getattr(pe, "DIRECTORY_ENTRY_IMPORT", None)
        sections = pe.sections
        return bool(imports or sections)
    finally:
        pe.close()


def _walk():
    for root in ROOTS:
        if not root.exists():
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [
                name
                for name in dirnames
                if name.lower() not in SKIP_DIRS and not name.startswith(".")
            ]
            for name in filenames:
                if name.lower().endswith(".exe"):
                    yield Path(dirpath) / name


def main() -> int:
    have = {path.stem.lower() for path in BENIGN.glob("*.exe")}
    malware = {path.stem.lower() for path in MALWARE.glob("*.exe")}
    need = TARGET - len(have)
    print(f"benign {len(have)} malware {len(malware)} need {need}", flush=True)
    if need <= 0:
        print("already full", flush=True)
        return 0
    added: list[tuple[str, int]] = []
    seen = set(have) | set(malware)
    for path in _walk():
        if len(added) >= need:
            break
        if not _usable(path):
            continue
        try:
            digest = _sha256(path)
        except OSError:
            continue
        if digest in seen:
            continue
        try:
            if not _parses(path):
                continue
        except Exception:
            continue
        dest = BENIGN / f"{digest}.exe"
        shutil.copyfile(path, dest)
        if _sha256(dest) != digest:
            dest.unlink(missing_ok=True)
            continue
        seen.add(digest)
        added.append((digest, dest.stat().st_size))
        if len(added) % 50 == 0:
            print(f"copied {len(added)}", flush=True)
    print(f"copied {len(added)} now {len(list(BENIGN.glob('*.exe')))}", flush=True)
    if len(have) + len(added) != TARGET:
        print(f"short of {TARGET}", flush=True)
        return 1
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    known = {row["sha256"] for row in manifest.get("benign") or []}
    for digest, _size in added:
        if digest not in known:
            manifest["benign"].append({"sha256": digest, "malice": 0.0})
    manifest["n_benign"] = len(manifest["benign"])
    manifest["n_benign_dike"] = len(have)
    manifest["n_benign_windows"] = len(added)
    manifest["benign_bytes"] = sum(path.stat().st_size for path in BENIGN.glob("*.exe"))
    manifest["benign_extra_source"] = (
        "local Windows PE from System32, SysWOW64, and Program Files"
    )
    manifest["rule"] = (
        "malware: Dike type 0 .exe, seed 42, MZ only. "
        "benign: 100 Dike malice 0 plus local Windows PE until 1000."
    )
    MANIFEST.write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")
    print("manifest n_benign", manifest["n_benign"], flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
