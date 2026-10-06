#!/usr/bin/env bash
# setuptools>=82 removed pkg_resources; Cuckoo 3 still imports it.
set -euo pipefail
source "$HOME/.cuckoo-venv/bin/activate"
cd "$HOME/cuckoo3"

echo "=== pin setuptools <82 ==="
pip install "setuptools==81.0.0"
python - <<'PY'
import pkg_resources
print("pkg_resources_ok", pkg_resources.__file__)
from pkg_resources import parse_version
print("parse_version_ok", parse_version("3.0.1"))
PY

echo "=== pkg_resources call sites ==="
grep -nR "pkg_resources" --include='*.py' "$HOME/cuckoo3" | head -40 || true

echo "=== cuckoo bin ==="
which cuckoo
cuckoo --help | head -20

echo "=== createcwd ==="
if [[ -d "$HOME/.cuckoocwd" ]]; then
  echo "cwd already exists: $HOME/.cuckoocwd"
else
  cuckoo createcwd
fi
ls -la "$HOME/.cuckoocwd" | head -20

echo "=== getmonitor ==="
if [[ -f "$HOME/cuckoo3/monitor.zip" ]]; then
  ls -lh "$HOME/cuckoo3/monitor.zip"
  cuckoo getmonitor "$HOME/cuckoo3/monitor.zip"
  echo "getmonitor_exit=$?"
else
  echo "monitor.zip missing"
fi

echo "=== signatures ==="
if [[ -d "$HOME/.cuckoocwd" && -f "$HOME/cuckoo3/signatures.zip" ]]; then
  mkdir -p "$HOME/.cuckoocwd/signatures"
  unzip -o "$HOME/cuckoo3/signatures.zip" -d "$HOME/.cuckoocwd/signatures" >/tmp/cuckoo_sig_unzip.log
  echo "signatures unzipped"
  find "$HOME/.cuckoocwd/signatures" -type d | head -20
fi

echo "=== monitor dest ==="
find "$HOME/.cuckoocwd" -iname '*monitor*' | head -20
ls -la "$HOME/.cuckoocwd" || true
ls "$HOME/.cuckoocwd/conf" || true

echo "DONE_FIX_SETUPTOOLS"
