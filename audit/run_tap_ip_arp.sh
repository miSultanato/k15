#!/usr/bin/env bash
# Boot a frozen image on TAP and run deterministic IPv4/ARP checks only.
set -euo pipefail

target=${1:?target directory required}
mode=${2:-expect}
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
target=$(cd "$target" && pwd)

cd "$target"
export B=build SMP=4 MEM=256
./tap.sh python3 "$repo_root/test_ip_arp_validation.py" . "$mode"
