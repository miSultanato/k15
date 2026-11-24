#!/usr/bin/env bash
# Boot a frozen image on a single-queue TAP link and run deterministic IPv4/ARP checks.
set -euo pipefail

target=${1:?target directory required}
mode=${2:-expect}
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
target=$(cd "$target" && pwd)

cd "$target"
export B=build SMP=1 MEM=256
arp_mode=expect
if [[ "$mode" == observe ]]; then arp_mode=reject; fi
tcp_mode=expect
if [[ "$mode" == observe ]]; then tcp_mode=reject; fi
./tap.sh bash -c 'python3 "$1/test_ip_arp_validation.py" . "$2" && python3 "$1/test_arp_short_frame.py" . "$3" && python3 "$1/test_tcp_ack_mss.py" . "$4" && python3 "$1/test_tcp_rst_sequence.py" .' _ "$repo_root" "$mode" "$arp_mode" "$tcp_mode"
