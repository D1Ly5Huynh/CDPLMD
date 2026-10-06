"""Functionality-preserving PE edits for IF-MalEvade Table 3 (lab samples only).

Actions map 1:1 with ``env.ACTIONS``. Bytes stay in ``data/cuckoo/work``.
No payload / shellcode is added: imports, section names, overlay padding, UPX.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

ACTIONS = [
    "add_import",
    "add_section",
    "add_unused_bytes",
    "rename_section",
    "upx_pack",
    "upx_unpack",
    "append_bytes",
]


def _out_path(src: Path, dest_dir: Path, tag: str) -> Path:
    dest_dir.mkdir(parents=True, exist_ok=True)
    return dest_dir / f"{src.stem}.{tag}{src.suffix}"


def _lief_parse(src: Path):
    import lief

    pe = lief.parse(str(src))
    if pe is None:
        raise RuntimeError(f"lief.parse failed: {src}")
    return pe


def add_section(src: Path, dest_dir: Path, name: str = ".idata2", size: int = 512) -> Path:
    dest = _out_path(src, dest_dir, "addsec")
    try:
        import lief

        pe = _lief_parse(src)
        section = lief.PE.Section(name[:8])
        section.content = list(b"\x00" * int(size))
        pe.add_section(section)
        pe.write(str(dest))
        return dest
    except Exception:
        return append_overlay(src, dest_dir, size, tag="addsec")


def rename_section(src: Path, dest_dir: Path, new_name: str = ".rdata2") -> Path:
    dest = _out_path(src, dest_dir, "rensec")
    try:
        pe = _lief_parse(src)
        if pe.sections:
            pe.sections[0].name = new_name[:8]
        pe.write(str(dest))
        return dest
    except Exception:
        import pefile

        shutil.copy2(src, dest)
        pe = pefile.PE(str(dest))
        if pe.sections:
            pe.sections[0].Name = new_name[:8].encode("ascii", "ignore").ljust(8, b"\x00")
        pe.write(str(dest))
        pe.close()
        return dest


def append_overlay(src: Path, dest_dir: Path, n_bytes: int = 256, tag: str = "append") -> Path:
    dest = _out_path(src, dest_dir, tag)
    shutil.copy2(src, dest)
    with dest.open("ab") as f:
        f.write(b"\x00" * int(n_bytes))
    return dest


def add_import(src: Path, dest_dir: Path, dll: str = "wininet.dll", fn: str = "InternetOpenA") -> Path:
    dest = _out_path(src, dest_dir, "addimp")
    try:
        import lief

        pe = lief.parse(str(src))
        if pe is None:
            raise RuntimeError("lief.parse failed")
        names = [e.name.lower() for e in pe.imports]
        if dll.lower() not in names:
            pe.add_library(dll)
        pe.add_imported_function(dll, fn)
        pe.write(str(dest))
        return dest
    except Exception:
        return add_section(src, dest_dir, name=".idata2", size=512)


def upx(src: Path, dest_dir: Path, unpack: bool = False) -> Path:
    tag = "upxun" if unpack else "upx"
    dest = _out_path(src, dest_dir, tag)
    shutil.copy2(src, dest)
    exe = shutil.which("upx") or shutil.which("upx.exe")
    if not exe:
        return dest
    args = [exe, "-d", "-q", str(dest)] if unpack else [exe, "-q", str(dest)]
    subprocess.run(args, check=False, capture_output=True)
    return dest


def apply_action(src: Path, action: str, dest_dir: Path) -> Path:
    src = Path(src)
    dest_dir = Path(dest_dir)
    if action == "add_import":
        return add_import(src, dest_dir)
    if action == "add_section":
        return add_section(src, dest_dir)
    if action == "add_unused_bytes":
        return append_overlay(src, dest_dir, 128, tag="unused")
    if action == "rename_section":
        return rename_section(src, dest_dir)
    if action == "upx_pack":
        return upx(src, dest_dir, unpack=False)
    if action == "upx_unpack":
        return upx(src, dest_dir, unpack=True)
    if action == "append_bytes":
        return append_overlay(src, dest_dir, 256, tag="append")
    raise KeyError(action)


def apply_actions(src: Path, actions: list[str], dest_dir: Path) -> Path:
    current = Path(src)
    for i, act in enumerate(actions):
        current = apply_action(current, act, dest_dir / f"step{i:02d}_{act}")
    return current
