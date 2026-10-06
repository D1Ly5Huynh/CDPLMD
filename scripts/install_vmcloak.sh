#!/usr/bin/env bash
# Install cert-ee VMCloak into the existing Cuckoo venv.
set -euo pipefail
python3.10 -m venv "$HOME/.vmcloak-venv"
# shellcheck disable=SC1091
source "$HOME/.vmcloak-venv/bin/activate"
pip install -U pip wheel
pip install "setuptools==81.0.0"
ROOT="$HOME/vmcloak"
if [[ ! -d "$ROOT/.git" ]]; then
  git clone --depth 1 https://github.com/cert-ee/vmcloak.git "$ROOT"
else
  git -C "$ROOT" pull --ff-only || true
fi
pip install -e "$ROOT"
pip install "setuptools==81.0.0"
which vmcloak
vmcloak --help | head -40
echo "DONE_INSTALL_VMCLOAK"
