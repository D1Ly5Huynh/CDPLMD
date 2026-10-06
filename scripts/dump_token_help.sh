#!/usr/bin/env bash
set -euo pipefail
source "$HOME/.cuckoo-venv/bin/activate"
cuckoo api token --help
cuckoomigrate --help
cuckoomigrate database --help
