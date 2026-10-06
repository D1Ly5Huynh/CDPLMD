#!/usr/bin/env bash
# VMCloak must NOT share the Cuckoo venv (sqlalchemy 1.4 vs 2.0, old pefile).
set -euo pipefail
source "$HOME/.cuckoo-venv/bin/activate"
pip install "setuptools==81.0.0" "sqlalchemy==2.0.37" "pefile==2024.8.26" "psutil>=6.1.1" "alembic>=1.14"
python - <<'PY'
import sqlalchemy, pefile, psutil
print("sqlalchemy", sqlalchemy.__version__)
print("pefile", pefile.__version__)
print("psutil", psutil.__version__)
PY
which cuckoo
cuckoo --help | head -8
echo "DONE_RESTORE_CUCKOO"
