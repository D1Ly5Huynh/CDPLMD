"""Functionality-preserving PE edits for IF-MalEvade Table 3 (lab samples only).

Actions map 1:1 with ``env.ACTIONS``. Bytes stay in ``data/cuckoo/work``.
No payload / shellcode is added: imports, section names, overlay padding, UPX.
"""

from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import sys
import threading
from pathlib import Path

# Table 3 names. Old lab names stay as aliases.
ACTIONS = [
    "insert_import",
    "rename_section",
    "insert_section",
    "section_append",
    "upx_pack",
    "upx_unpack",
    "overly_append",
]
_ALIASES = {
    "add_import": "insert_import",
    "add_section": "insert_section",
    "add_unused_bytes": "section_append",
    "append_bytes": "overly_append",
}


def _out_path(src: Path, dest_dir: Path, tag: str) -> Path:
    """One short name per action, based on the sha256 stem only.

    Appending every tag onto the previous stem reaches Windows MAX_PATH
    (260) around turn 30, so a 50-turn episode never finishes.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    stem = src.name.split(".", 1)[0]
    dest = dest_dir / f"{stem}.{tag}{src.suffix}"
    if dest.resolve() == Path(src).resolve():
        dest = dest_dir / f"{stem}.{tag}2{src.suffix}"
    return dest


# Rebuilt import directory. Kept outside the corpus section vocabulary so
# insert_import flips one import bit and leaves section bits alone.
_IMPORT_SECTION = ".ifmimp"


def _lief_parse(src: Path):
    import lief

    lief.logging.disable()
    pe = lief.parse(str(src))
    if pe is None:
        raise RuntimeError(f"lief.parse failed: {src}")
    return pe


def _section_label(section) -> str:
    return str(section.name).split("\x00", 1)[0]


def _pick_section(pe, old_name: str | None):
    if old_name:
        want = old_name[:8]
        for section in pe.sections:
            if _section_label(section) == want:
                return section
    if pe.sections:
        return pe.sections[0]
    return None


def add_section(src: Path, dest_dir: Path, name: str = ".idata2", size: int = 512) -> Path:
    import lief

    dest = _out_path(src, dest_dir, "addsec")
    pe = _lief_parse(src)
    section = lief.PE.Section(name[:8])
    section.content = list(b"\x00" * int(size))
    pe.add_section(section)
    pe.write(str(dest))
    return dest


def rename_section(
    src: Path,
    dest_dir: Path,
    new_name: str = ".rdata2",
    old_name: str | None = None,
) -> Path:
    dest = _out_path(src, dest_dir, "rensec")
    new_name = new_name[:8]
    try:
        pe = _lief_parse(src)
        target = _pick_section(pe, old_name)
        if target is not None:
            target.name = new_name
        pe.write(str(dest))
        return dest
    except Exception:
        import pefile

        shutil.copy2(src, dest)
        pe = pefile.PE(str(dest))
        target = None
        if old_name:
            want = old_name[:8].encode("ascii", "ignore")
            for section in pe.sections:
                if section.Name.split(b"\x00", 1)[0] == want:
                    target = section
                    break
        if target is None and pe.sections:
            target = pe.sections[0]
        if target is not None:
            target.Name = new_name.encode("ascii", "ignore").ljust(8, b"\x00")
        pe.write(str(dest))
        pe.close()
        return dest


def append_overlay(src: Path, dest_dir: Path, n_bytes: int = 256, tag: str = "append") -> Path:
    dest = _out_path(src, dest_dir, tag)
    shutil.copy2(src, dest)
    with dest.open("ab") as f:
        f.write(b"\x00" * int(n_bytes))
    return dest


def _has_import(path: Path, dll: str, fn: str) -> bool:
    import pefile

    pe = pefile.PE(str(path), fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
    )
    want_dll = dll.lower()
    found = False
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        got = entry.dll.decode("utf-8", "ignore").lower()
        if got != want_dll:
            continue
        for imp in entry.imports:
            name = imp.name.decode("utf-8", "ignore") if imp.name else f"ord{imp.ordinal}"
            if name == fn:
                found = True
                break
        if found:
            break
    pe.close()
    return found


def add_import(src: Path, dest_dir: Path, dll: str = "wininet.dll", fn: str = "InternetOpenA") -> Path:
    """Add one import and rebuild the import directory with LIEF 1.0.

    ``Binary.write`` keeps the old import table. The builder, with imports
    enabled, is what ``pefile`` reads back into the paper feature bit.
    """
    import lief

    dest = _out_path(src, dest_dir, "addimp")
    pe = _lief_parse(src)
    lib = None
    for existing in pe.imports:
        if str(existing.name).lower() == dll.lower():
            lib = existing
            break
    if lib is None:
        lib = pe.add_import(dll)
    if not any(str(entry.name) == fn for entry in lib.entries):
        lib.add_entry(fn)
    bcfg = lief.PE.Builder.config_t()
    bcfg.imports = True
    bcfg.idata_section = _IMPORT_SECTION
    builder = lief.PE.Builder(pe, bcfg)
    builder.build()
    builder.write(str(dest))
    if not _has_import(dest, dll, fn):
        raise RuntimeError(f"import {dll}!{fn} missing after rebuild")
    return dest


def _upx_exe() -> str | None:
    found = shutil.which("upx") or shutil.which("upx.exe")
    if found:
        return found
    local = Path(__file__).resolve().parents[1] / "tools" / "upx" / "upx.exe"
    if local.is_file():
        return str(local)
    return None


def upx(src: Path, dest_dir: Path, unpack: bool = False) -> Path:
    tag = "upxun" if unpack else "upx"
    dest = _out_path(src, dest_dir, tag)
    shutil.copy2(src, dest)
    exe = _upx_exe()
    if not exe:
        return dest
    args = [exe, "-d", "-q", str(dest)] if unpack else [exe, "-q", "--force", str(dest)]
    subprocess.run(args, check=False, capture_output=True)
    return dest


def _split_import(import_name: str | None) -> tuple[str, str]:
    if not import_name:
        return "wininet.dll", "InternetOpenA"
    if "!" in import_name:
        dll, fn = import_name.split("!", 1)
        return dll or "kernel32.dll", fn or "CreateFileA"
    return "kernel32.dll", import_name


def apply_action(
    src: Path,
    action: str,
    dest_dir: Path,
    import_name: str | None = None,
    section_name: str | None = None,
    old_section: str | None = None,
) -> Path:
    src = Path(src)
    dest_dir = Path(dest_dir)
    action = _ALIASES.get(action, action)
    if action == "insert_import":
        dll, fn = _split_import(import_name)
        return add_import(src, dest_dir, dll=dll, fn=fn)
    if action == "insert_section":
        return add_section(src, dest_dir, name=(section_name or ".idata2")[:8])
    if action == "section_append":
        return append_overlay(src, dest_dir, 128, tag="unused")
    if action == "rename_section":
        return rename_section(
            src,
            dest_dir,
            new_name=(section_name or ".rdata2")[:8],
            old_name=old_section,
        )
    if action == "upx_pack":
        return upx(src, dest_dir, unpack=False)
    if action == "upx_unpack":
        return upx(src, dest_dir, unpack=True)
    if action == "overly_append":
        return append_overlay(src, dest_dir, 256, tag="append")
    raise KeyError(action)


def apply_actions(src: Path, actions: list[str], dest_dir: Path) -> Path:
    current = Path(src)
    for i, act in enumerate(actions):
        current = apply_action(current, act, dest_dir / f"step{i:02d}_{act}")
    return current


class EditSession:
    """Table 3 edits in a child process.

    On some of these PEs, LIEF aborts the interpreter with
    STATUS_HEAP_CORRUPTION (0xc0000374). The child dies, that one action
    is skipped, and DQN keeps the 500 episodes.
    """

    def __init__(self, timeout_s: float = 120.0) -> None:
        self.timeout_s = timeout_s
        self.proc: subprocess.Popen | None = None
        self.crashes = 0

    def _start(self) -> None:
        self.close()
        root = str(Path(__file__).resolve().parents[1])
        env = os.environ.copy()
        env["PYTHONPATH"] = root + os.pathsep + env.get("PYTHONPATH", "")
        env["PYTHONUNBUFFERED"] = "1"
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "if_malevade.pe_worker"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            cwd=root,
            env=env,
        )

    def close(self) -> None:
        proc = self.proc
        self.proc = None
        if proc is None:
            return
        if proc.poll() is None and proc.stdin is not None:
            try:
                proc.stdin.close()
            except Exception:
                pass
        try:
            proc.wait(timeout=2)
        except Exception:
            proc.kill()
            proc.wait(timeout=2)

    def _kill(self) -> None:
        proc = self.proc
        self.proc = None
        if proc is None:
            return
        proc.kill()
        try:
            proc.wait(timeout=5)
        except Exception:
            pass

    def apply(
        self,
        src: Path,
        action: str,
        dest_dir: Path,
        import_name: str | None = None,
        section_name: str | None = None,
        old_section: str | None = None,
    ) -> Path:
        job = {
            "src": str(src),
            "action": action,
            "dest_dir": str(dest_dir),
            "import_name": import_name,
            "section_name": section_name,
            "old_section": old_section,
        }
        if self.proc is None or self.proc.poll() is not None:
            self._start()
        proc = self.proc
        if proc is None or proc.stdin is None or proc.stdout is None:
            raise RuntimeError("pe edit process did not start")
        proc.stdin.write(json.dumps(job) + "\n")
        proc.stdin.flush()
        box: queue.Queue[str] = queue.Queue(maxsize=1)
        stdout = proc.stdout

        def _read() -> None:
            try:
                box.put(stdout.readline())
            except Exception:
                box.put("")

        thread = threading.Thread(target=_read, daemon=True)
        thread.start()
        thread.join(self.timeout_s)
        if thread.is_alive():
            self.crashes += 1
            self._kill()
            raise RuntimeError("pe edit timed out")
        line = box.get() if not box.empty() else ""
        if not line:
            self.crashes += 1
            self._kill()
            raise RuntimeError("pe edit process crashed")
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as exc:
            self.crashes += 1
            self._kill()
            raise RuntimeError("pe edit returned a bad line") from exc
        if not msg.get("ok"):
            raise RuntimeError(str(msg.get("error") or "pe edit failed"))
        return Path(str(msg["dest"]))
