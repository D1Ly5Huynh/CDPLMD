#!/usr/bin/env bash
set -euo pipefail
source "$HOME/.cuckoo-venv/bin/activate"
export CUCKOO_CWD="$HOME/.cuckoocwd"
mkdir -p "$HOME/.cuckoocwd/log"
echo "=== urls ==="
cat /home/tuonghk/cuckoo3/web/cuckoo/web/api/urls.py
echo "=== submit urls ==="
cat /home/tuonghk/cuckoo3/web/cuckoo/web/api/submit/urls.py
echo "=== analysis urls ==="
cat /home/tuonghk/cuckoo3/web/cuckoo/web/api/analysis/urls.py
echo "=== starting api ==="
exec cuckoo api -h 0.0.0.0 -p 8090
