#!/usr/bin/env bash
set -euo pipefail
source "$HOME/.cuckoo-venv/bin/activate"
echo "=== qemu.yaml ==="
cat "$HOME/.cuckoocwd/conf/machineries/qemu.yaml"
echo "=== api help ==="
cuckoo api --help
echo "=== web help ==="
cuckoo web --help | head -40
echo "=== cuckoo startup try (short) ==="
# Don't hang: just import startup and dump default API host/port from source
python - <<'PY'
import inspect, cuckoo
print("cuckoo file", cuckoo.__file__)
try:
    from cuckoo.main import main
    print("main ok")
except Exception as e:
    print("main err", e)
import pkgutil, os
root = os.path.dirname(cuckoo.__file__)
print("core root", root)
PY
grep -nR "8090\|8000\|8080\|api" "$HOME/cuckoo3/core/cuckoo" --include='*.py' | grep -iE 'port|host|bind|listen' | head -40
echo "DONE"
