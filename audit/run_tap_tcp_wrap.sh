#!/usr/bin/env bash
# Exercise ACK-window behavior with a synthetic server ISN near 2^32.
set -euo pipefail

target=${1:?target directory required}
mode=${2:-expect}
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
target=$(cd "$target" && pwd)
cd "$target"

export B=build-wrap SMP=1 MEM=256
tcp_mode=wrap-expect
if [[ "$mode" == observe ]]; then tcp_mode=wrap-reject; fi
if [[ "$mode" != expect && "$mode" != observe ]]; then echo "mode must be expect or observe" >&2; exit 2; fi
./tap.sh bash -c 'python3 "$1/test_tcp_ack_mss.py" . "$2"' _ "$repo_root" "$tcp_mode"
