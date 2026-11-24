#!/usr/bin/env bash
# Complete a transcript-faithful malformed ClientHello handshake against local QEMU only.
set -euo pipefail

target=${1:?target directory required}
expected=${2:?expected mode required: accept or reject}
client=${3:?compiled Go client path required}
case "$expected" in accept|reject) ;; *) echo "expected mode must be accept or reject" >&2; exit 2 ;; esac
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
target=$(cd "$target" && pwd)

cd "$target"
export B=build IMG=build/os.bin PORT=8443 HPORT=9443 KVM=0 SMP=4 MEM=256
source tools/vm.sh
boot
# Independent purpose-built client: raw alert code, CertificateVerify and Finished.
timeout 20s python3 "$repo_root/test_malformed_clienthello_handshake.py" "$target" "$expected"
# Go crypto/tls cross-check: validates the synthetic CA chain and exact HTTP body.
timeout 20s "$client" "$target" "$expected"
