#!/usr/bin/env bash
# Exercise ACK-window behavior with a synthetic server ISN near 2^32.
set -euo pipefail

target=${1:?target directory required}
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
target=$(cd "$target" && pwd)
cd "$target"

export B=build-wrap SMP=1 MEM=256
./tap.sh bash -c 'python3 "$1/test_tcp_ack_mss.py" . wrap' _ "$repo_root"
