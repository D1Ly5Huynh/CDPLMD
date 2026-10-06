#!/usr/bin/env bash
set -e
source "$HOME/.cuckoo-venv/bin/activate"
echo "=== pip cuckoo pkgs ==="
pip list | grep -i cuckoo || true
echo "=== bins ==="
ls "$HOME/.cuckoo-venv/bin" | grep -i cuckoo || true
echo "=== core dir ==="
ls "$HOME/cuckoo3/core"
echo "=== try import ==="
python - <<'PY'
import pkgutil
print("cuckoo pkg", bool(pkgutil.find_loader("cuckoo")))
try:
    import cuckoo
    print("cuckoo file", getattr(cuckoo, "__file__", None))
except Exception as e:
    print("import_err", type(e).__name__, e)
PY
echo "=== createcwd help ==="
python -m cuckoo --help 2>&1 | head -40 || true
which cuckoo || true
