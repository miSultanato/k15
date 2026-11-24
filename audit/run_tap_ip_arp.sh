#!/usr/bin/env bash
# Boot a frozen image on a single-queue TAP link and run deterministic IPv4/ARP checks.
set -euo pipefail

target=${1:?target directory required}
mode=${2:-expect}
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
target=$(cd "$target" && pwd)

cd "$target"
export B=build SMP=1 MEM=256
./tap.sh bash -c 'python3 "$1/test_ip_arp_validation.py" . "$2" && python3 "$1/test_arp_short_frame.py" . "$2"' _ "$repo_root" "$mode"
