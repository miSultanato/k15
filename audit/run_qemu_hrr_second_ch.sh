#!/usr/bin/env bash
# Force a TLS 1.3 HelloRetryRequest using the local QEMU guest via user-mode networking.
set -euo pipefail

target=${1:?target directory required}
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
target=$(cd "$target" && pwd)
cd "$target"

export B=build IMG=build/os.bin PORT=8443 HPORT=9443 KVM=0 SMP=4 MEM=256
source tools/vm.sh
boot

set +e
printf "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n" |
  timeout 12 openssl s_client -connect "127.0.0.1:$PORT" -servername "$NAME" \
    -groups P-256:X25519 -CAfile "$B/ca.pem" -msg -trace -quiet \
    >"$B/hrr-client.log" 2>&1
set -e
python3 "$repo_root/test_hrr_second_clienthello.py" "$B/hrr-client.log"
