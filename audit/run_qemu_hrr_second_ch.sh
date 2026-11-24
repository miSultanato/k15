#!/usr/bin/env bash
# Force a TLS 1.3 HelloRetryRequest using a Go client with P-256 first, X25519 second.
set -euo pipefail

target=${1:?target directory required}
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
target=$(cd "$target" && pwd)
cd "$target"

export B=build IMG=build/os.bin PORT=8443 HPORT=9443 KVM=0 SMP=4 MEM=256
source tools/vm.sh
boot
go run "$repo_root/hrr_second_clienthello.go"
