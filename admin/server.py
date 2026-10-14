"""Local admin UI. Bind 127.0.0.1 only. Reads JSON results, never PE bytes.

    python admin/server.py
"""

from __future__ import annotations

import json
import mimetypes
import sys
import time
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
STATIC = Path(__file__).resolve().parent / "static"
sys.path.insert(0, str(ROOT))

from admin.status import build_dashboard  # noqa: E402

HOST = "127.0.0.1"
PORT = 8765
_CACHE: dict[str, object] = {"at": 0.0, "body": None}


def dashboard_payload() -> dict:
    now = time.time()
    cached = _CACHE.get("body")
    if isinstance(cached, dict) and now - float(_CACHE["at"]) < 8:
        return cached
    body = build_dashboard(ROOT)
    body["cuckoo_api"] = _cuckoo_api()
    body["generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    _CACHE["at"] = now
    _CACHE["body"] = body
    return body


def _cuckoo_api() -> dict:
    try:
        from if_malevade.cuckoo_client import CuckooClient

        info = CuckooClient(timeout=3).health()
    except Exception as exc:  # noqa: BLE001 — UI must stay up if WSL is down
        return {"status": "offline", "error": type(exc).__name__}
    return {
        "status": info.get("status") or "offline",
        "probe": info.get("probe"),
        "http_status": info.get("http_status"),
    }


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/api/status":
            raw = json.dumps(dashboard_payload(), ensure_ascii=False).encode("utf-8")
            self._send(200, "application/json; charset=utf-8", raw)
            return
        if path in {"/", "/index.html"}:
            self._file(STATIC / "index.html")
            return
        rel = path.lstrip("/")
        target = (STATIC / rel).resolve()
        if STATIC.resolve() not in target.parents and target != STATIC.resolve():
            self._send(404, "text/plain; charset=utf-8", b"not found")
            return
        if target.is_file():
            self._file(target)
            return
        self._send(404, "text/plain; charset=utf-8", b"not found")

    def _file(self, path: Path) -> None:
        forced = {".js": "text/javascript", ".css": "text/css", ".html": "text/html"}
        mime = forced.get(path.suffix) or mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        if mime.startswith("text/") or mime in {"application/javascript", "application/json"}:
            mime += "; charset=utf-8"
        self._send(200, mime, path.read_bytes())

    def _send(self, code: int, content_type: str, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), partial(Handler))
    print(f"CDPLMD admin  http://{HOST}:{PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
