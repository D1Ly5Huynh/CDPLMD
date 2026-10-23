"""Score one uploaded PE and point at an existing mutant. Does not execute the file."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import joblib
import numpy as np

from if_malevade.data import vectorize_pe
from if_malevade.demo_policy import mutate_pe, policy_path
from if_malevade.detectors import malware_score

from admin.status import eval_hashes

MAX_BYTES = 80 * 1024 * 1024
DETECTORS = ("RandomForest", "GradientBoosting", "MLP", "DecisionTree")
THRESHOLD = 0.8


def file_from_multipart(body: bytes, content_type: str) -> bytes:
    if "boundary=" not in content_type:
        raise ValueError("Thiếu boundary của form.")
    boundary = content_type.split("boundary=", 1)[1].split(";", 1)[0].strip().strip('"')
    sep = ("--" + boundary).encode("ascii", "ignore")
    for part in body.split(sep):
        if b'name="file"' not in part:
            continue
        if b"\r\n\r\n" not in part:
            continue
        payload = part.split(b"\r\n\r\n", 1)[1]
        if payload.endswith(b"\r\n"):
            payload = payload[:-2]
        if payload.endswith(b"--"):
            payload = payload[:-2]
        if not payload:
            raise ValueError("File trống.")
        if len(payload) > MAX_BYTES:
            raise ValueError("File lớn hơn 80 MB.")
        return payload
    raise ValueError("Không thấy file trong form.")


def demo_output_path(root: Path, sha: str) -> Path | None:
    if len(sha) != 64 or any(ch not in "0123456789abcdef" for ch in sha):
        return None
    path = (root / "results" / "lab_dataset" / "demo_out" / f"{sha}.mut.exe").resolve()
    folder = (root / "results" / "lab_dataset" / "demo_out").resolve()
    if folder not in path.parents or not path.is_file():
        return None
    return path


def mutant_path(root: Path, sha: str) -> Path | None:
    if len(sha) != 64 or any(ch not in "0123456789abcdef" for ch in sha):
        return None
    hashes = eval_hashes(root, 50)
    if sha not in hashes:
        return None
    path = (root / "results" / "lab_dataset" / "mutants" / f"{sha}.mut.exe").resolve()
    root_mut = (root / "results" / "lab_dataset" / "mutants").resolve()
    if root_mut not in path.parents or not path.is_file():
        return None
    return path


def _scores(root: Path, vector: np.ndarray) -> list[dict]:
    model = root / "models" / "lab_dataset" / "detectors.joblib"
    detectors = joblib.load(model)
    rows = []
    for name in DETECTORS:
        score = float(malware_score(detectors[name], vector)[0])
        rows.append({"name": name, "score": score, "detected": score >= THRESHOLD})
    return rows


def inspect_bytes(root: Path, payload: bytes) -> dict:
    if len(payload) < 64 or payload[:2] != b"MZ":
        raise ValueError("File không có header MZ của PE.")
    sha = hashlib.sha256(payload).hexdigest()
    vocab_path = root / "data" / "lab_dataset" / "vocab.json"
    vocab = json.loads(vocab_path.read_text(encoding="utf-8"))
    from if_malevade.config import Config

    cfg = Config()
    cfg.n_imports = 3269
    cfg.n_sections = 254
    vector = vectorize_pe(None, vocab, cfg, raw=payload).reshape(1, -1)
    before = _scores(root, vector)
    after = None
    actions: list[str] = []
    turns = None
    evaded = None
    ready = False
    if policy_path(root).is_file():
        incoming = root / "results" / "lab_dataset" / "demo_in" / f"{sha}.exe"
        incoming.parent.mkdir(parents=True, exist_ok=True)
        incoming.write_bytes(payload)
        out = root / "results" / "lab_dataset" / "demo_out" / f"{sha}.mut.exe"
        info = mutate_pe(root, incoming, out)
        actions = list(info.get("actions_named") or [])
        turns = info.get("turn")
        evaded = bool(info.get("evaded"))
        after = _scores(root, np.asarray(info["vector"], dtype=np.float32).reshape(1, -1))
        ready = demo_output_path(root, sha) is not None
        note = "Đã sửa file bằng DQN đã lưu. Bản output tải ở nút bên dưới. File không được chạy."
    else:
        note = "Chưa có models/lab_dataset/demo_policy.npz. Chưa tạo được bản mutate."
    return {
        "sha256": sha,
        "size": len(payload),
        "bits_on": int(vector.sum()),
        "scores": before,
        "scores_after": after,
        "actions": actions,
        "turns": turns,
        "evaded": evaded,
        "mutant_ready": ready,
        "download": f"/api/demo-out/{sha}" if ready else None,
        "note": note,
    }
