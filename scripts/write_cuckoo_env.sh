#!/usr/bin/env bash
set -euo pipefail
TOKEN=$(cat /mnt/c/Users/tuonghk/CDPLMD/data/cuckoo/api.token | tr -d '\r\n ')
cat > "$HOME/.cuckoo-venv/cuckoo.env" <<EOF
export VIRTUAL_ENV="\$HOME/.cuckoo-venv"
export PATH="\$HOME/.cuckoo-venv/bin:\$PATH"
export CUCKOO_CWD="\$HOME/.cuckoocwd"
export CUCKOO_API="http://127.0.0.1:8090"
export CUCKOO_API_TOKEN="$TOKEN"
EOF
echo "wrote $HOME/.cuckoo-venv/cuckoo.env"
