"""Child process for one Table 3 edit at a time.

LIEF stays in this process. If it aborts, the parent starts a new one.
"""

from __future__ import annotations

import json
import os
import sys


def _silence_stderr() -> None:
    fd = os.open(os.devnull, os.O_WRONLY)
    try:
        os.dup2(fd, 2)
    finally:
        os.close(fd)


def main() -> None:
    _silence_stderr()
    from if_malevade.pe_mutate import apply_action

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            job = json.loads(line)
            dest = apply_action(
                job["src"],
                job["action"],
                job["dest_dir"],
                import_name=job.get("import_name"),
                section_name=job.get("section_name"),
                old_section=job.get("old_section"),
            )
            msg = {"ok": True, "dest": str(dest)}
        except Exception as exc:
            msg = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        sys.stdout.write(json.dumps(msg) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
