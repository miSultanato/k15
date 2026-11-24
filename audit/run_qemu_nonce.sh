#!/usr/bin/env bash
# Boot the synthetic-key bounty image under QEMU TCG and audit CertificateVerify nonces.
# No production certificate, key or host is used.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
target=${1:-target}
count=${2:-512}
target=$(cd "$target" && pwd)

cd "$target"
export B=build IMG=build/os.bin PORT=8443 HPORT=9443 KVM=0 SMP=4 MEM=256
source tools/vm.sh
boot
python3 "$repo_root/qemu_nonce_uniqueness.py" "$target" "$count" 4
