#!/usr/bin/env bash
set -euo pipefail
echo "=== api.log ==="
ls -la "$HOME/.cuckoocwd/log" || true
tail -80 "$HOME/.cuckoocwd/log/api.log" || true
echo "=== cuckoo.log ==="
tail -40 "$HOME/.cuckoocwd/log/cuckoo.log" 2>/dev/null || true
echo "DONE"
