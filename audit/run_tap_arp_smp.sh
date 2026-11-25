#!/usr/bin/env bash
# Run only the short-ARP stale-buffer probe with a multi-processor guest.
set -euo pipefail

target=${1:?target directory required}
mode=${2:-expect}
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
target=$(cd "$target" && pwd)

case "$mode" in
  expect) arp_mode=expect ;;
  observe) arp_mode=reject ;;
  *) echo "mode must be expect or observe" >&2; exit 2 ;;
esac

cd "$target"
export B=build SMP=${SMP:-2} MEM=256
./tap.sh bash -c 'python3 "$1/test_arp_short_frame.py" . "$2"' _ "$repo_root" "$arp_mode"
