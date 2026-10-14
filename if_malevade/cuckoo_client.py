"""Cuckoo Sandbox client for IF-MalEvade §IV behaviour check.

Paper: submit original PE and mutated PE, keep the mutant only when Cuckoo
``signatures`` still match the original (fully-working malware).

Submit and report use the Cuckoo 3 API on :8090 (``POST /submit/file``,
``GET /analysis/<id>``, ``GET /analysis/<id>/task/<task_id>/post``).
A dead API can still shell out to ``wsl -d Ubuntu-22.04 -- cuckoo``.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any, Callable
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


# Analysis states from cuckoo.common.analyses.States. The scheduler keeps
# searching until one of these is stored on the analysis.
_TERMINAL_OK = {"finished"}
_TERMINAL_BAD = {"fatal_error", "no_selected", "waiting_manual"}


def windows10_settings(timeout: int = 120) -> dict[str, Any]:
    """Settings dict the Cuckoo 3 submit view accepts for this lab guest."""
    return {
        "timeout": int(timeout),
        "platforms": [{"platform": "windows", "os_version": "10"}],
    }


def _safe_filename(name: str) -> str:
    base = Path(name).name.replace('"', "").replace("\\", "_")
    cleaned = "".join(ch for ch in base if ch not in "\r\n")
    return cleaned or "sample.bin"


def encode_multipart(fields: dict[str, str], filename: str, content: bytes) -> tuple[bytes, str]:
    """Multipart body for ``POST /submit/file`` (file + JSON settings string)."""
    boundary = "ifm" + uuid.uuid4().hex
    chunks: list[bytes] = []
    for key, value in fields.items():
        chunks.append(
            (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{key}"\r\n\r\n'
                f"{value}\r\n"
            ).encode()
        )
    safe = _safe_filename(filename)
    chunks.append(
        (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{safe}"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n"
        ).encode()
    )
    chunks.append(content)
    chunks.append(f"\r\n--{boundary}--\r\n".encode())
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"


def _http_error_body(exc: HTTPError) -> dict[str, Any]:
    raw = exc.read() or b""
    try:
        body = json.loads(raw.decode("utf-8", errors="replace"))
        if not isinstance(body, dict):
            body = {"body": body}
    except json.JSONDecodeError:
        body = {"error": raw[:300].decode("utf-8", errors="replace")}
    body["http_status"] = int(exc.code)
    body["ok"] = False
    return body


def _task_ids(analysis: dict) -> list[str]:
    ids: list[str] = []
    for task in analysis.get("tasks") or []:
        if isinstance(task, dict) and task.get("id"):
            ids.append(str(task["id"]))
        elif isinstance(task, str) and task:
            ids.append(task)
    return ids


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

    def submit_file(self, path: Path, timeout_s: int = 120) -> dict:
        """Upload one file to Cuckoo 3. Returns ``analysis_id`` when accepted."""
        path = Path(path)
        if not path.is_file():
            return {"ok": False, "error": f"missing {path}"}
        settings = json.dumps(windows10_settings(timeout_s), separators=(",", ":"))
        body, content_type = encode_multipart(
            {"settings": settings}, path.name, path.read_bytes()
        )
        url = f"{self.base_url}/submit/file"
        try:
            payload = _http_json(
                url,
                data=body,
                timeout=max(int(self.timeout), 60),
                method="POST",
                headers={"Content-Type": content_type},
            )
        except HTTPError as exc:
            return _http_error_body(exc)
        except (URLError, TimeoutError, OSError, json.JSONDecodeError, ValueError):
            wsl_path = "/mnt/" + str(path.resolve()).replace("\\", "/").replace(":", "").lower()
            if len(str(path.resolve())) >= 3 and str(path.resolve())[1] == ":":
                drive = str(path.resolve())[0].lower()
                rest = str(path.resolve())[2:].replace("\\", "/")
                wsl_path = f"/mnt/{drive}{rest}"
            cli = self._wsl_cuckoo(["submit", "--platform", "windows,10", f"'{wsl_path}'"])
            return {"ok": bool(cli.get("ok")), "cli": cli, "path": wsl_path}
        if not isinstance(payload, dict):
            return {"ok": False, "error": "submit_not_json"}
        analysis_id = payload.get("analysis_id")
        if not analysis_id:
            payload["ok"] = False
            payload.setdefault("error", "submit_missing_analysis_id")
            return payload
        return {"ok": True, "analysis_id": str(analysis_id), "settings": payload.get("settings")}

    def analysis(self, analysis_id: str) -> dict:
        try:
            body = _http_json(
                f"{self.base_url}/analysis/{analysis_id}", timeout=self.timeout
            )
        except HTTPError as exc:
            return _http_error_body(exc)
        except (URLError, TimeoutError, OSError, ValueError) as exc:
            return {"ok": False, "error": str(exc)}
        return body if isinstance(body, dict) else {"body": body}

    def task_post(self, analysis_id: str, task_id: str) -> dict:
        try:
            body = _http_json(
                f"{self.base_url}/analysis/{analysis_id}/task/{task_id}/post",
                timeout=self.timeout,
            )
        except HTTPError as exc:
            return _http_error_body(exc)
        except (URLError, TimeoutError, OSError, ValueError) as exc:
            return {"ok": False, "error": str(exc)}
        return body if isinstance(body, dict) else {"body": body}

    def wait_report(
        self,
        analysis_id: str,
        poll: float = 10.0,
        max_wait: float = 600.0,
        on_state: Callable[[str, dict], None] | None = None,
    ) -> dict:
        """Poll until the analysis is finished, then collect post signatures."""
        deadline = time.time() + max_wait
        last = ""
        view: dict[str, Any] = {}
        while time.time() < deadline:
            view = self.analysis(analysis_id)
            state = str(view.get("state") or "")
            if state and state != last:
                last = state
                if on_state is not None:
                    on_state(state, view)
            if state in _TERMINAL_OK or state in _TERMINAL_BAD:
                break
            time.sleep(poll)
        else:
            return {
                "ok": False,
                "error": "timeout",
                "analysis_id": analysis_id,
                "state": last,
                "signatures": [],
            }
        state = str(view.get("state") or "")
        if state in _TERMINAL_BAD:
            return {
                "ok": False,
                "error": state,
                "analysis_id": analysis_id,
                "state": state,
                "errors": view.get("errors"),
                "signatures": [],
                "tasks": view.get("tasks") or [],
            }
        signatures: list[Any] = []
        posts: list[dict] = []
        for task_id in _task_ids(view):
            post = self.task_post(analysis_id, task_id)
            posts.append(post)
            signatures.extend(post.get("signatures") or [])
        report = {
            "ok": True,
            "analysis_id": analysis_id,
            "state": state,
            "tasks": view.get("tasks") or [],
            "signatures": signatures,
            "posts": posts,
        }
        if not _task_ids(view):
            report["ok"] = False
            report["error"] = "finished_without_tasks"
        return report

    def compare_pair(
        self,
        orig_pe: Path,
        adv_pe: Path,
        min_recall: float = 1.0,
        poll: float = 10.0,
        max_wait: float = 600.0,
    ) -> dict:
        s0 = self.submit_file(orig_pe)
        s1 = self.submit_file(adv_pe)
        out: dict[str, Any] = {"orig_submit": s0, "adv_submit": s1, "match": False}
        id0 = s0.get("analysis_id")
        id1 = s1.get("analysis_id")
        if not (s0.get("ok") and s1.get("ok") and id0 and id1):
            out["error"] = "submit_failed"
            return out
        r0 = self.wait_report(str(id0), poll=poll, max_wait=max_wait)
        r1 = self.wait_report(str(id1), poll=poll, max_wait=max_wait)
        out["orig_state"] = r0.get("state")
        out["adv_state"] = r1.get("state")
        out["orig_signatures"] = sorted(signature_names(r0))
        out["adv_signatures"] = sorted(signature_names(r1))
        if r0.get("state") != "finished" or r1.get("state") != "finished":
            out["error"] = "analysis_not_finished"
            out["match"] = False
            return out
        out["match"] = signatures_match(r0, r1, min_recall=min_recall)
        return out
