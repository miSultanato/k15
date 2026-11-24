#!/usr/bin/env bash
# Force a TLS 1.3 HelloRetryRequest by offering P-256 first and X25519 second.
set -euo pipefail

target=${1:?target directory required}
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
target=$(cd "$target" && pwd)
cd "$target"

export B=build IMG=build/os.bin SMP=1 MEM=256
./tap.sh bash -c '
  set +e
  printf "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n" |
    timeout 12 openssl s_client -connect "$GUEST:443" -servername "$NAME" \
      -groups P-256:X25519 -CAfile "$B/ca.pem" -msg -trace -quiet \
      >"$B/hrr-client.log" 2>&1
  python3 "$1/test_hrr_second_clienthello.py" "$B/hrr-client.log"
' _ "$repo_root"
