"""Cuckoo Sandbox client for IF-MalEvade §IV behaviour check.

Paper: submit original PE and mutated PE, keep the mutant only when Cuckoo
``signatures`` still match the original (fully-working malware).

Talks to Cuckoo 2 REST (:8090) or Cuckoo 3 web/API, and can shell out to
``wsl -d Ubuntu-22.04 -- cuckoo``.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def _token() -> str:
    env = os.environ.get("CUCKOO_API_TOKEN", "").strip()
    if env:
        return env
    p = Path(__file__).resolve().parents[1] / "data" / "cuckoo" / "api.token"
    try:
        return p.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _http_json(
    url: str,
    data: bytes | None = None,
    timeout: int = 15,
    method: str = "GET",
    headers: dict[str, str] | None = None,
) -> Any:
    req = Request(url, data=data, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    token = _token()
    hdrs = {str(k).lower(): v for k, v in (headers or {}).items()}
    if token and "authorization" not in hdrs:
        req.add_header("Authorization", f"Token {token}")
    if data is not None and req.get_header("Content-type") is None:
        req.add_header("Content-Type", "application/octet-stream")
    with urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
        code = getattr(resp, "status", 200)
    if not raw:
        return {"http_status": code}
    try:
        body = json.loads(raw.decode("utf-8", errors="replace"))
        if isinstance(body, dict):
            body["http_status"] = code
            return body
        return {"http_status": code, "body": body}
    except json.JSONDecodeError:
        return {"http_status": code, "raw": raw[:200].decode("utf-8", errors="replace")}


def signature_names(report: dict) -> set[str]:
    names: set[str] = set()
    for sig in report.get("signatures") or []:
        if isinstance(sig, dict):
            n = sig.get("name") or sig.get("description") or ""
            if n:
                names.add(str(n).lower())
        elif isinstance(sig, str) and sig.strip():
            names.add(sig.strip().lower())
    return names


def signatures_match(orig: dict, adv: dict, min_recall: float = 1.0) -> bool:
    """True when adversarial Cuckoo signatures cover the original set.

    Paper keeps a mutant if behaviour signatures still match the parent.
    ``min_recall=1.0`` requires every original signature name to appear.
    """
    a = signature_names(orig)
    b = signature_names(adv)
    if not a:
        return bool(b) or True
    return (len(a & b) / len(a)) >= min_recall


class CuckooClient:
    def __init__(
        self,
        base_url: str | None = None,
        distro: str = "Ubuntu-22.04",
        timeout: int = 20,
    ) -> None:
        env = os.environ.get("CUCKOO_API", "").strip()
        self.base_url = (base_url or env or "http://127.0.0.1:8090").rstrip("/")
        self.distro = distro
        self.timeout = timeout

    def health(self) -> dict:
        info: dict[str, Any] = {"api": self.base_url, "status": "offline"}
        probe_t = min(int(self.timeout), 3)
        # Cuckoo 3 REST: /submit/*, /analysis/*, /analyses/* on :8090 (dev `cuckoo api`).
        # Cuckoo 2 REST: /cuckoo/status, /tasks/*.
        for path in (
            "/submit/platforms",
            "/analyses/",
            "/cuckoo/status",
            "/status",
            "/",
        ):
            try:
                body = _http_json(self.base_url + path, timeout=probe_t)
                info["status"] = "online"
                info["probe"] = path
                info["http_status"] = body.get("http_status") if isinstance(body, dict) else None
                info["body_keys"] = sorted(k for k in body.keys() if k != "raw") if isinstance(body, dict) else type(body).__name__
                return info
            except (URLError, TimeoutError, OSError, ValueError) as e:
                # Django 404/401/403/500 still means the API process is up.
                reason = getattr(e, "reason", None)
                code = getattr(reason, "status", None) or getattr(e, "code", None)
                if code in {400, 401, 403, 404, 405, 500}:
                    info["status"] = "online"
                    info["probe"] = path
                    info["http_status"] = code
                    return info
                continue
        cli = self._wsl_cuckoo(["--help"])
        if cli.get("ok"):
            info["status"] = "cli"
            info["cli"] = (cli.get("stdout") or "")[:200]
            return info
        info["cli_error"] = cli.get("stderr") or cli.get("error")
        return info

    def available(self) -> bool:
        return self.health().get("status") in {"online", "cli"}

    def _wsl_cuckoo(self, args: list[str]) -> dict:
        cmd = [
            "wsl.exe",
            "-d",
            self.distro,
            "--",
            "bash",
            "-lc",
            "source $HOME/.cuckoo-venv/bin/activate 2>/dev/null; cuckoo " + " ".join(args),
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout + 30)
        except (OSError, subprocess.TimeoutExpired) as e:
            return {"ok": False, "error": str(e)}
        return {
            "ok": proc.returncode == 0,
            "code": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }

    def submit_file(self, path: Path) -> dict:
        path = Path(path)
        if not path.is_file():
            return {"ok": False, "error": f"missing {path}"}
        try:
            data = path.read_bytes()
            url = f"{self.base_url}/tasks/create/file"
            req = Request(url, data=data, method="POST")
            req.add_header("Content-Type", "application/octet-stream")
            req.add_header("X-File-Name", path.name)
            with urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode("utf-8", errors="replace"))
            task_id = body.get("task_id") or body.get("data", {}).get("task_id")
            return {"ok": True, "task_id": task_id, "body": body}
        except (URLError, TimeoutError, OSError, json.JSONDecodeError):
            wsl_path = "/mnt/" + str(path.resolve()).replace("\\", "/").replace(":", "").lower()
            if len(str(path.resolve())) >= 3 and str(path.resolve())[1] == ":":
                drive = str(path.resolve())[0].lower()
                rest = str(path.resolve())[2:].replace("\\", "/")
                wsl_path = f"/mnt/{drive}{rest}"
            cli = self._wsl_cuckoo(["submit", f"'{wsl_path}'"])
            return {"ok": cli.get("ok"), "cli": cli, "path": wsl_path}

    def report(self, task_id: int) -> dict:
        try:
            return _http_json(f"{self.base_url}/tasks/report/{task_id}", timeout=self.timeout)
        except (URLError, TimeoutError, OSError, ValueError) as e:
            return {"error": str(e)}

    def wait_report(self, task_id: int, poll: float = 10.0, max_wait: float = 600.0) -> dict:
        deadline = time.time() + max_wait
        while time.time() < deadline:
            try:
                view = _http_json(f"{self.base_url}/tasks/view/{task_id}", timeout=self.timeout)
            except (URLError, TimeoutError, OSError, ValueError):
                view = {}
            status = ""
            if isinstance(view, dict):
                status = str((view.get("task") or view).get("status") or "")
            if status in {"reported", "finished", "completed"}:
                return self.report(task_id)
            time.sleep(poll)
        return {"error": "timeout", "task_id": task_id}

    def compare_pair(self, orig_pe: Path, adv_pe: Path, min_recall: float = 1.0) -> dict:
        s0 = self.submit_file(orig_pe)
        s1 = self.submit_file(adv_pe)
        out = {"orig_submit": s0, "adv_submit": s1, "match": False}
        if not (s0.get("ok") and s1.get("ok") and s0.get("task_id") and s1.get("task_id")):
            out["error"] = "submit_failed_or_no_task_id"
            return out
        r0 = self.wait_report(int(s0["task_id"]))
        r1 = self.wait_report(int(s1["task_id"]))
        out["orig_signatures"] = sorted(signature_names(r0))
        out["adv_signatures"] = sorted(signature_names(r1))
        out["match"] = signatures_match(r0, r1, min_recall=min_recall)
        return out
