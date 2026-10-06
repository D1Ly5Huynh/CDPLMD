#!/usr/bin/env bash
set -euo pipefail
source "$HOME/.cuckoo-venv/bin/activate"
export CUCKOO_CWD="$HOME/.cuckoocwd"
echo "=== cuckoomigrate database all ==="
cuckoomigrate database all
echo "=== migrate api django ==="
cuckoo api djangocommand migrate
echo "=== api token ==="
cuckoo api token --create cdplmd --admin || true
cuckoo api token --list || true
echo "=== starting api 0.0.0.0:8090 ==="
exec cuckoo api -h 0.0.0.0 -p 8090
