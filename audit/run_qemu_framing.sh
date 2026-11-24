#!/usr/bin/env bash
# Boot the freshly built, pinned bounty image under QEMU TCG and test one malformed
# ClientHello against localhost only. The vm.sh trap tears QEMU down on exit.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
target=${1:-target}
target=$(cd "$target" && pwd)

cd "$target"
export B=build IMG=build/os.bin PORT=8443 HPORT=9443 KVM=0 SMP=4 MEM=256
source tools/vm.sh
boot
python3 "$repo_root/test_clienthello_framing.py" "$target"
