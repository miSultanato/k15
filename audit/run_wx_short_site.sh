#!/usr/bin/env bash
# Observe whether a one-file site ending in RET shares an executable page.
# All images are built locally and booted under QEMU; no network probes are sent.
set -euo pipefail

target=${1:?target directory required}
label=${2:?label required}
cd "$target"

export B=build-wx-short
export SMP=1 MEM=256 KVM=0
mkdir -p "$B/one"
python3 - "$B/one/index.html" <<'PY'
from pathlib import Path
import sys
Path(sys.argv[1]).write_bytes(b"<!doctype html><title>short-site</title>\n\xc3")
PY

make -s -B B="$B" SITE="$B/one" COMPRESS=0 WXTEST=4 >/dev/null
source tools/vm.sh
PORT=18500
HPORT=19500
IMG="$B/os.bin"
log=$(mktemp)
qemu "$B/disk.img" "$(slirp)" >"$log" 2>&1 &
pid=$!
sleep 4
if kill -0 "$pid" 2>/dev/null; then
  state=alive
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
else
  state=reset
  wait "$pid" 2>/dev/null || true
fi
printf '%s: short-site WXTEST=4 guest=%s\n' "$label" "$state"
if [[ -s "$log" ]]; then
  echo "QEMU diagnostic (first 300 bytes):"
  head -c 300 "$log" | tr '\n' ' '
  echo
fi
rm -f "$log"
