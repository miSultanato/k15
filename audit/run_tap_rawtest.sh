#!/usr/bin/env bash
# Run the project's raw Ethernet/IP/TCP frame fuzzer against a local QEMU image on TAP.
set -euo pipefail

target=${1:?target directory required}
seed=${2:-20261124}
target=$(cd "$target" && pwd)

cd "$target"
export B=build SMP=4 MEM=256
./tap.sh python3 tools/rawtest.py "$seed"
