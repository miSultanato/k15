#!/usr/bin/env bash
# Run malformed raw frames and deterministic IPv4/ARP checks against a local TAP guest.
set -euo pipefail

target=${1:?target directory required}
seed=${2:-20261124}
mode=${3:-expect}
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
target=$(cd "$target" && pwd)

cd "$target"
export B=build SMP=4 MEM=256
./tap.sh bash -c 'python3 tools/rawtest.py "$1" && python3 "$2/test_ip_arp_validation.py" . "$3"' _ "$seed" "$repo_root" "$mode"
