#!/usr/bin/env bash
# Live page-table probe for a synthetic short SITE; QEMU is local and isolated.
set -euo pipefail

target=${1:?target directory required}
label=${2:?label required}
expected=${3:?expected state required: alive or reset}
if [[ "$expected" != alive && "$expected" != reset ]]; then
  echo "expected must be alive or reset" >&2
  exit 2
fi
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
target=$(cd "$target" && pwd)
cd "$target"

export B=build-wx-pte
export SMP=1 MEM=256 KVM=0
mkdir -p "$B/one"
python3 - "$B/one/index.html" <<'PYGEN'
from pathlib import Path
import sys
Path(sys.argv[1]).write_bytes(b"<!doctype html><title>pte-probe</title>\n\xc3")
PYGEN

make -s -B B="$B" SITE="$B/one" COMPRESS=0 >/dev/null
python3 "$repo_root/probe_wx_pte.py" "$target" "$expected"
echo "PASS: $label live page-table inspection completed"
