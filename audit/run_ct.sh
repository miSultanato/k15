#!/usr/bin/env bash
# Reproduce the source project's Valgrind taint/constant-time test using the
# runner's packaged Valgrind. The six deliberately bad controls must be caught.
set -euo pipefail

target=${1:-target}
target=$(cd "$target" && pwd)
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

cd "$target"
mkdir -p build
gcc -no-pie -fno-pie -O1 -mno-red-zone -o build/ct test/ct.c build/os_host.o

if ! valgrind --error-exitcode=9 build/ct >"$tmp" 2>&1; then
  echo "FAIL: normal constant-time run produced a Valgrind error"
  cat "$tmp"
  exit 1
fi
if ! grep -Eq 'ERROR SUMMARY: 0 errors from 0 contexts' "$tmp"; then
  echo "FAIL: normal run did not have a clean Valgrind summary"
  cat "$tmp"
  exit 1
fi
echo "PASS: normal crypto run has zero Valgrind errors"

for control in 1 2 3 4 5 6; do
  if valgrind --error-exitcode=9 build/ct "$control" >"$tmp" 2>&1; then
    echo "FAIL: Valgrind did not detect deliberately bad control $control"
    cat "$tmp"
    exit 1
  fi
  if ! grep -Eq 'ERROR SUMMARY: [1-9][0-9]* errors from' "$tmp"; then
    echo "FAIL: control $control exited without a Valgrind error report"
    cat "$tmp"
    exit 1
  fi
  echo "PASS: Valgrind detected deliberately bad control $control"
done
