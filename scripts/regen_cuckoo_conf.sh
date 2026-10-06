#!/usr/bin/env bash
set -euo pipefail
source "$HOME/.cuckoo-venv/bin/activate"
echo "=== regen configs ==="
cuckoo createcwd --regen-configs
echo "=== conf after regen ==="
find "$HOME/.cuckoocwd/conf" -type f | sort
echo "=== list yaml ==="
ls -la "$HOME/.cuckoocwd/conf"
for f in "$HOME/.cuckoocwd/conf"/* "$HOME/.cuckoocwd/conf"/*/*; do
  [[ -f "$f" ]] || continue
  echo "----- $f -----"
  head -60 "$f"
done
echo "=== elasticsearch ==="
command -v elasticsearch || true
dpkg -l | grep -i elastic || true
ss -lnt | head || netstat -lnt | head || true
echo "DONE_REGEN"
