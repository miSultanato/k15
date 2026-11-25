#!/usr/bin/env bash
# Run the raw-TCP TLS ACK-desynchronization probe against one local QEMU image.
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 TARGET expect|observe" >&2
  exit 2
fi
target="$1"
mode="$2"
repo_root=$(cd "$(dirname "$0")" && pwd)
target=$(cd "$target" && pwd)

cd "$target"
export B=build SMP=1 MEM=256
./tap.sh python3 "$repo_root/test_tls_tcp_ack_desync.py" "$target" "$mode"
