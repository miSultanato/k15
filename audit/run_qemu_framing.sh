#!/usr/bin/env bash
# Boot a locally built k15 image under QEMU TCG and probe ClientHello framing.
# All connections remain on localhost; no production host is contacted.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
target=${1:-target}
expected=${2:-accept}
target=$(cd "$target" && pwd)

cd "$target"
export B=build IMG=build/os.bin PORT=8443 HPORT=9443 KVM=0 SMP=4 MEM=256
source tools/vm.sh
boot
python3 "$repo_root/test_clienthello_framing.py" "$target" "$expected"
python3 "$repo_root/test_malformed_clienthello_handshake.py" "$target" "$expected"
if [[ "$expected" == "accept" ]]; then
  python3 "$repo_root/test_tls_record_rejection.py" "$target" expect
  python3 "$repo_root/test_dummy_ccs.py" "$target" expect
else
  python3 "$repo_root/test_tls_record_rejection.py" "$target" observe
  python3 "$repo_root/test_dummy_ccs.py" "$target" observe
fi
python3 "$repo_root/test_https_request.py" "$target"
