#!/usr/bin/env bash
set -euo pipefail
SIG="$HOME/.cuckoocwd/signatures"
mkdir -p "$SIG/cuckoo/pattern" "$SIG/cuckoo/yara"
rm -f "$SIG/cuckoo/pattern/.empty"
ln -sfn ../../pattern/windows "$SIG/cuckoo/pattern/windows"
ln -sfn ../../pattern/network "$SIG/cuckoo/pattern/network"
ln -sfn ../../yara/static "$SIG/cuckoo/yara/static"
echo "=== links ==="
ls -l "$SIG/cuckoo/pattern" "$SIG/cuckoo/yara"
echo "windows files:" "$(find "$SIG/cuckoo/pattern/windows" -type f | awk 'END{print NR}')"
echo "network files:" "$(find "$SIG/cuckoo/pattern/network" -type f | awk 'END{print NR}')"
echo "DONE_SIG_LINKS"
