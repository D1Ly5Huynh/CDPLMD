#!/usr/bin/env bash
# Finish Cuckoo 3 core CLI after the first WSL package pass.
set -euo pipefail
source "$HOME/.cuckoo-venv/bin/activate"
cd "$HOME/cuckoo3"

pip install -U wheel
pip install "setuptools==81.0.0"
for pkg in ./common ./processing ./machineries ./web ./node ./core; do
  echo "INSTALL $pkg"
  pip install -e "$pkg"
done

echo "=== cuckoo bin ==="
which cuckoo
cuckoo --help | head -30

echo "=== createcwd ==="
cuckoo createcwd || true
ls -la "$HOME/.cuckoocwd" | head

echo "=== monitor/signatures ==="
if [[ -f "$HOME/cuckoo3/monitor.zip" ]]; then
  cuckoo getmonitor "$HOME/cuckoo3/monitor.zip" || true
fi
if [[ -d "$HOME/.cuckoocwd" && -f "$HOME/cuckoo3/signatures.zip" ]]; then
  mkdir -p "$HOME/.cuckoocwd/signatures"
  unzip -o "$HOME/cuckoo3/signatures.zip" -d "$HOME/.cuckoocwd/signatures" || true
fi

echo "DONE_CUCKOO_CORE"
cuckoo --help | head -15
ls "$HOME/.cuckoocwd" || true
