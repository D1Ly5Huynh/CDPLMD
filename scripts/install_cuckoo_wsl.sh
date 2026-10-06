#!/usr/bin/env bash
# Install Cuckoo 3 (cert-ee) on Ubuntu 22.04 WSL2 for IF-MalEvade §IV Cuckoo check.
# Run inside Ubuntu-22.04:  bash /mnt/c/Users/tuonghk/CDPLMD/scripts/install_cuckoo_wsl.sh
set -euo pipefail

if [[ "$(id -u)" -eq 0 ]]; then
  echo "run as the normal WSL user, not root (script uses sudo)"
  exit 1
fi

. /etc/os-release
echo "os=$PRETTY_NAME python=$(python3 --version 2>/dev/null || true)"
if [[ "${VERSION_ID:-}" != "22.04" ]]; then
  echo "Cuckoo 3 documents Ubuntu 22.04; this is $VERSION_ID"
fi

sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
  build-essential software-properties-common unzip \
  libhyperscan5 libhyperscan-dev \
  libjpeg8-dev zlib1g-dev p7zip-full cabextract \
  libssl-dev libcapstone-dev libvirt-dev pkg-config \
  python3.10 python3.10-venv python3.10-dev python3-pip \
  qemu-system-x86 qemu-utils qemu-system-common \
  genisoimage tcpdump yara git curl wget \
  libmagic1 libfuzzy-dev

if [[ -e /dev/kvm ]]; then
  echo "kvm_ok $(ls -l /dev/kvm)"
  sudo usermod -aG kvm "$USER" || true
else
  echo "kvm_missing — nested virt not exposed; Cuckoo can install, analysis VMs will not run until /dev/kvm exists"
fi

ROOT="${CUCKOO_SRC:-$HOME/cuckoo3}"
if [[ ! -d "$ROOT/.git" ]]; then
  git clone --depth 1 https://github.com/cert-ee/cuckoo3.git "$ROOT"
else
  git -C "$ROOT" pull --ff-only || true
fi

python3.10 -m venv "$HOME/.cuckoo-venv"
# shellcheck disable=SC1091
. "$HOME/.cuckoo-venv/bin/activate"
pip install -U pip wheel
# setuptools>=82 dropped pkg_resources; Cuckoo 3 still imports parse_version from it.
pip install "setuptools==81.0.0"
pip install libvirt-python || echo "libvirt-python skipped"

if [[ -x "$ROOT/install.sh" ]]; then
  echo "running cert-ee install.sh (core packages, no Win10 ISO in this step)"
  bash "$ROOT/install.sh" || true
fi

# Core / processing / machineries are separate packages in the monorepo.
for sub in core processing machineries web node; do
  if [[ -f "$ROOT/$sub/pyproject.toml" || -f "$ROOT/$sub/setup.py" ]]; then
    echo "pip install -e $ROOT/$sub"
    pip install -e "$ROOT/$sub" || true
  fi
done

if command -v cuckoo >/dev/null 2>&1; then
  cuckoo createcwd || true
  echo "cuckoo_bin=$(command -v cuckoo)"
  cuckoo --help | head -20 || true
else
  echo "cuckoo CLI not on PATH yet; activate $HOME/.cuckoo-venv"
fi

mkdir -p "$HOME/.cuckoo-venv"
cat > "$HOME/.cuckoo-venv/cuckoo.env" <<EOF
export VIRTUAL_ENV="\$HOME/.cuckoo-venv"
export PATH="\$HOME/.cuckoo-venv/bin:\$PATH"
export CUCKOO_CWD="\$HOME/.cuckoocwd"
EOF

echo "DONE_INSTALL_PACKAGES"
echo "Next: configure a Windows guest snapshot (VMCloak) then: cuckoo"
echo "API/web typically nginx :8080 after full quickstart; CLI: cuckoo submit FILE"
