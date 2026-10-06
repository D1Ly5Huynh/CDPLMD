#!/usr/bin/env bash
# Resume after aborting --recommended. Paper-min: disableservices + snapshot.
set -euo pipefail
source "$HOME/.vmcloak-venv/bin/activate"
LOG="$HOME/vmcloak_win10.log"

echo "=== abort leftover qemu ===" | tee -a "$LOG"
pkill -f "qemu-system-x86_64" || true
sleep 2
pgrep -af qemu-system-x86_64 | grep -v pgrep && echo "qemu still up" >&2 || echo "qemu stopped" | tee -a "$LOG"

echo "=== vmcloak install disableservices (paper-min) ===" | tee -a "$LOG"
vmcloak --debug install win10base disableservices 2>&1 | tee -a "$LOG"

echo "=== vmcloak snapshot ===" | tee -a "$LOG"
vmcloak --debug snapshot --count 1 win10base win10vm_ 192.168.30.10 2>&1 | tee -a "$LOG"

echo "DONE_WIN10_GUEST" | tee -a "$LOG"
ls -lh "$HOME/.vmcloak/vms/qemu/" || true
