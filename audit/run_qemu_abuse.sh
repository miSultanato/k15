#!/usr/bin/env bash
# Run upstream's full hostile-client regression suite against the fixed image.
# QEMU is isolated on a GitHub runner; the suite connects only to localhost.
set -euo pipefail

target=${1:-fixed}
target=$(cd "$target" && pwd)

cd "$target"
export B=build IMG=build/os.bin PORT=8443 HPORT=9443 KVM=0 SMP=4 MEM=256
source tools/vm.sh
boot
python3 tools/abuse.py
