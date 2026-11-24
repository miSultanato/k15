#!/usr/bin/env bash
# Run the project's deterministic hostile ClientHello fuzzer against a local QEMU image.
# The TAP device and all traffic live inside the runner's private network namespace.
set -euo pipefail

target=${1:?target directory required}
seed=${2:-20261124}
count=${3:-20000}
target=$(cd "$target" && pwd)

cd "$target"
export B=build SMP=4 MEM=256
./tap.sh python3 tools/hellofuzz.py "$count" "$seed"
