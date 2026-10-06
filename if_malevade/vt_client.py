"""VirusTotal v3 client for IF-MalEvade Table 6–7 (eqs. 3–4).

Paper uploads original and mutated PE, then:

    detection rate = n / N          (eq. 3)
    evasive rate   = (N_org - N_adv) / N_org   (eq. 4)

n = engines that label the sample malware. N = 61 in the paper.

Hash lookup of an already-known SHA-256 does not upload bytes.
Uploading a mutant requires the PE file.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

VT_API = "https://www.virustotal.com/api/v3"


def _key() -> str:
    for name in ("VT_API_KEY", "VIRUSTOTAL_API_KEY", "VT_KEY"):
        v = os.environ.get(name, "").strip()
        if v:
            return v
    for p in (
        Path(__file__).resolve().parents[1] / "data" / "vt.api",
        Path(__file__).resolve().parents[1] / "data" / "cuckoo" / "vt.api",
    ):
        try:
            k = p.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if k:
            return k
    return ""


def _request(
    method: str,
    url: str,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 60,
) -> dict[str, Any]:
    req = Request(url, data=data, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urlopen(req, timeout=timeout) as res:
            raw = res.read().decode("utf-8", "replace")
    except HTTPError as e:
        body = e.read().decode("utf-8", "replace") if e.fp else ""
        return {"ok": False, "http_status": int(e.code), "error": body or str(e)}
    except (URLError, TimeoutError, OSError) as e:
        return {"ok": False, "error": str(e)}
    try:
        obj = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        return {"ok": False, "error": "invalid_json", "raw": raw[:500]}
    if isinstance(obj, dict):
        obj["ok"] = True
        obj["http_status"] = 200
        return obj
    return {"ok": True, "http_status": 200, "data": obj}


def engine_counts(report: dict) -> dict[str, int | float]:
    """n, N from a VT file report (paper eq. 3)."""
    data = report.get("data") if isinstance(report.get("data"), dict) else report
    attrs = data.get("attributes") if isinstance(data, dict) else {}
    stats = (attrs or {}).get("last_analysis_stats") or {}
    results = (attrs or {}).get("last_analysis_results") or {}
    n = int(stats.get("malicious") or 0)
    if results:
        n_res = sum(
            1
            for r in results.values()
            if str((r or {}).get("category") or "").lower() == "malicious"
        )
        if n_res:
            n = n_res
        n_engines = len(results)
    else:
        n_engines = int(
            sum(int(stats.get(k) or 0) for k in ("malicious", "undetected", "harmless", "suspicious"))
        )
    n_engines = max(n_engines, 1)
    return {
        "n": n,
        "N": n_engines,
        "detection_rate": float(n) / float(n_engines),
        "detection_rate_paper_N61": float(n) / 61.0,
    }


class VirusTotalClient:
    def __init__(self, api_key: str | None = None, rate_sleep: float = 15.0) -> None:
        self.api_key = (api_key or _key()).strip()
        self.rate_sleep = float(rate_sleep)
        self._last = 0.0

    def has_key(self) -> bool:
        return bool(self.api_key)

    def _headers(self) -> dict[str, str]:
        return {"x-apikey": self.api_key, "Accept": "application/json"}

    def _throttle(self) -> None:
        wait = self.rate_sleep - (time.time() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.time()

    def report_hash(self, sha256: str) -> dict[str, Any]:
        sha = sha256.strip().lower()
        if len(sha) != 64:
            return {"ok": False, "error": "bad_sha256", "sha256": sha256}
        if not self.api_key:
            return {"ok": False, "error": "missing_api_key"}
        self._throttle()
        out = _request("GET", f"{VT_API}/files/{sha}", headers=self._headers())
        out["sha256"] = sha
        if out.get("ok"):
            out.update(engine_counts(out))
        return out

    def upload_file(self, path: Path) -> dict[str, Any]:
        path = Path(path)
        if not self.api_key:
            return {"ok": False, "error": "missing_api_key", "path": str(path)}
        if not path.is_file():
            return {"ok": False, "error": "missing_file", "path": str(path)}
        data = path.read_bytes()
        boundary = "----ifmalevade7a9"
        filename = path.name
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode("utf-8") + data + f"\r\n--{boundary}--\r\n".encode("ascii")
        self._throttle()
        headers = self._headers()
        headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
        out = _request("POST", f"{VT_API}/files", data=body, headers=headers, timeout=120)
        out["path"] = str(path)
        out["size"] = len(data)
        return out

    def lookup_hashes(self, sha_list: list[str], dest: Path | None = None) -> dict[str, Any]:
        rows = []
        for sha in sha_list:
            rows.append(self.report_hash(sha))
        if dest is not None:
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(json.dumps(rows, indent=2), encoding="utf-8")
        ok = [r for r in rows if r.get("ok")]
        rates = [float(r["detection_rate"]) for r in ok]
        ns = [int(r["n"]) for r in ok]
        return {
            "n_query": len(sha_list),
            "n_ok": len(ok),
            "n_missing_on_vt": sum(1 for r in rows if r.get("http_status") == 404),
            "detection_rate": {
                "min": float(min(rates)) if rates else None,
                "max": float(max(rates)) if rates else None,
                "mean": float(sum(rates) / len(rates)) if rates else None,
            },
            "n_engines_hits": {
                "min": int(min(ns)) if ns else None,
                "max": int(max(ns)) if ns else None,
                "mean": float(sum(ns) / len(ns)) if ns else None,
            },
            "rows": rows,
        }


def table6_7(orig: dict, adv: dict | None, n_engines_paper: int = 61) -> tuple[dict, dict]:
    """Build Table 6 detection-rate and Table 7 evasive-rate summaries."""
    o_rates = [
        float(r["n"]) / n_engines_paper
        for r in orig.get("rows") or []
        if r.get("ok")
    ]
    table6 = {
        "n_engines_paper": n_engines_paper,
        "n_original_ok": orig.get("n_ok"),
        "detection_rate_original": orig.get("detection_rate"),
        "detection_rate_original_paper_N61": {
            "min": float(min(o_rates)) if o_rates else None,
            "max": float(max(o_rates)) if o_rates else None,
            "mean": float(sum(o_rates) / len(o_rates)) if o_rates else None,
        },
    }
    table7: dict = {"status": "need_adversarial_pe"}
    if adv and adv.get("n_ok"):
        a_rows = [r for r in adv.get("rows") or [] if r.get("ok")]
        o_map = {
            r["sha256"]: r
            for r in orig.get("rows") or []
            if r.get("ok") and r.get("sha256")
        }
        ev = []
        for r in a_rows:
            parent = r.get("parent_sha256") or r.get("sha256")
            o = o_map.get(parent) or o_map.get(r.get("sha256", ""))
            if not o:
                continue
            n_org = float(o["n"])
            n_adv = float(r["n"])
            if n_org > 0:
                ev.append(max((n_org - n_adv) / n_org, 0.0))
        a_rates = [float(r["n"]) / n_engines_paper for r in a_rows]
        table6["detection_rate_adversarial_paper_N61"] = {
            "min": float(min(a_rates)) if a_rates else None,
            "max": float(max(a_rates)) if a_rates else None,
            "mean": float(sum(a_rates) / len(a_rates)) if a_rates else None,
        }
        table7 = {
            "evasion_rate": {
                "min": float(min(ev)) if ev else None,
                "max": float(max(ev)) if ev else None,
                "mean": float(sum(ev) / len(ev)) if ev else None,
            },
            "n_pairs": len(ev),
            "n_engines": n_engines_paper,
        }
    return table6, table7
