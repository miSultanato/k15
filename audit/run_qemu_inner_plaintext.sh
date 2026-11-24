#!/usr/bin/env bash
# Run authenticated malformed TLSInnerPlaintext probes against one local QEMU image.
set -euo pipefail

target=${1:?target directory required}
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
target=$(cd "$target" && pwd)
cd "$target"

export B=build IMG=build/os.bin PORT=8443 HPORT=9443 KVM=0 SMP=4 MEM=256
source tools/vm.sh
boot
python3 "$repo_root/test_tls_inner_plaintext.py" "$target"
