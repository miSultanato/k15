#!/usr/bin/env bash
# Force a TLS 1.3 HelloRetryRequest using OpenSSL with P-384 first, X25519 second.
set -euo pipefail

target=${1:?target directory required}
expected_ccs=${2:?expected CCS mode required: none or some}
case "$expected_ccs" in none|some) ;; *) echo "expected CCS mode must be none or some" >&2; exit 2 ;; esac
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
target=$(cd "$target" && pwd)
cd "$target"

export B=build IMG=build/os.bin PORT=8443 HPORT=9443 KVM=0 SMP=4 MEM=256
source tools/vm.sh
boot
timeout 30s python3 "$repo_root/test_hrr_second_clienthello.py" "$target" "$expected_ccs"
