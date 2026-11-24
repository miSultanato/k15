#!/usr/bin/env bash
# Reboot the local QEMU guest while preserving the TAP link and replay a captured SYN cookie.
set -euo pipefail

target=${1:?target directory required}
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
target=$(cd "$target" && pwd)
cd "$target"

export B=build SMP=1 MEM=256
export MON="$target/build/syn-cookie-monitor.sock"
rm -f "$MON"
trap 'rm -f "$MON"' EXIT

./tap.sh python3 "$repo_root/test_syn_cookie_reboot.py"
