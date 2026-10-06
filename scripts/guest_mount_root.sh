#!/usr/bin/env bash
# wsl -d Ubuntu-22.04 -u root -- bash this
set -euo pipefail
ISO=/home/tuonghk/win10x64.iso
MNT=/mnt/win10x64
mkdir -p "$MNT"
if findmnt "$MNT" >/dev/null 2>&1; then
  echo "already mounted"
else
  mount -o loop,ro "$ISO" "$MNT"
fi
ls "$MNT" | head
echo "DONE_MOUNT"
