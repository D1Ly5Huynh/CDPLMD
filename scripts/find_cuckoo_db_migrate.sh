#!/usr/bin/env bash
set -euo pipefail
source "$HOME/.cuckoo-venv/bin/activate"
echo "=== bins ==="
ls "$HOME/.cuckoo-venv/bin" | grep -iE 'cuckoo|migrate'
echo "=== migrate.py ==="
cat /home/tuonghk/cuckoo3/core/cuckoo/scripts/migrate.py
echo "=== pyproject scripts ==="
grep -A20 '\[project.scripts\]' /home/tuonghk/cuckoo3/core/pyproject.toml
echo "=== cuckoo --help full ==="
cuckoo --help
echo "=== grep migrate ==="
grep -nR "requires migration\|alembic\|cuckoodb\|migrate" /home/tuonghk/cuckoo3/core/cuckoo --include='*.py' | head -50
echo "=== main.py commands ==="
grep -n "def \|@main\|@click" /home/tuonghk/cuckoo3/core/cuckoo/main.py | head -80
echo "DONE"
