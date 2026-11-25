#!/usr/bin/env bash
# Run the raw-TCP TLS ACK-desynchronization probe against one local QEMU image.
set -euo pipefail

target=\${1:?target directory required}
mode=\${2:?mode required: expect or observe}
repo_root=$(cd "$(dirname "\${BASH_SOURCE[0]}")" && pwd)
target=$(cd "$target" && pwd)

cd "$target"
export B=build SMP=1 MEM=256
./tap.sh python3 "$repo_root/test_tls_tcp_ack_desync.py" "$target" "$mode"
