#!/usr/bin/env bash
# Boot the frozen image on TAP, collect local synthetic-key signatures, then snapshot guest RAM.
# Requires execution inside a private network namespace with CAP_NET_ADMIN/CAP_NET_RAW.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
target=${1:-target}
count=${2:-1024}
target=$(cd "$target" && pwd)

mon="/tmp/k15-memory-monitor-$$"
ram="k15-guest-ram-$.bin"
export B=build SMP=4 MEM=256 MON="$mon"
export HOST=10.0.2.15
export REPO_ROOT="$repo_root" TARGET="$target" COUNT="$count" RAM="$ram"
trap 'rm -f "$mon" "$target/$ram"' EXIT

cd "$target"
./tap.sh bash -c '
  PORT=443 python3 "$REPO_ROOT/qemu_nonce_uniqueness.py" "$TARGET" "$COUNT" 4 &&
  python3 "$REPO_ROOT/qemu_memory_scan.py" "$TARGET" "$MON" "$RAM"
'
