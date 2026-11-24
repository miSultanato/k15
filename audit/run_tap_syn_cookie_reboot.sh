#!/usr/bin/env bash
# Keep the TAP link and QEMU process alive across a monitor-triggered guest reset.
# Unlike the generic vm.sh launcher, this local probe deliberately omits -no-reboot:
# QEMU must survive system_reset so the same VM can boot again on the same TAP link.
set -euo pipefail

target=\${1:?target directory required}
repo_root=$(cd "$(dirname "\${BASH_SOURCE[0]}")" && pwd)
target=$(cd "$target" && pwd)
cd "$target"

export B=build SMP=1 MEM=256 KVM=0
export MON="$target/build/syn-cookie-monitor.sock"
TAP=k2t
rm -f "$MON"

PORT= source tools/vm.sh

# Same Q35/virtio devices as tools/vm.sh, but without -no-reboot.
qemu() {
  local disk=$1 net=$2
  shift 2
  exec qemu-system-x86_64 -nodefaults -display none -machine q35 \
    -smp "\${SMP:-1}" "\${ACCEL[@]}" -m "\${MEM:-256}" "$@" \
    -drive "file=$disk,format=raw,if=none,id=d0,snapshot=on" -netdev "$net,id=n0" \
    -device pcie-root-port,id=rp1,chassis=1 \
    -device virtio-net-pci,bus=rp1,netdev=n0,disable-legacy=on,romfile= \
    -device pcie-root-port,id=rp2,chassis=2 \
    -device virtio-scsi-pci,bus=rp2 \
    -device scsi-hd,drive=d0
}

ip link del "$TAP" 2>/dev/null || true
ip tuntap add dev "$TAP" mode tap
ip link set "$TAP" multicast off
ip addr add 10.0.2.2/24 dev "$TAP"
for i in $(seq 32 63); do ip addr add "10.0.2.$i/24" dev "$TAP"; done
ip link set "$TAP" up

python3 tools/dhcpd.py "$TAP" >/dev/null 2>&1 &
DPID=$!
LOG=$(mktemp)
qemu "$B/disk.img" "tap,ifname=$TAP,script=no,downscript=no" \
  -monitor "unix:$MON,server,nowait" >"$LOG" 2>&1 &
QEMU_PID=$!
trap 'kill "$QEMU_PID" "$DPID" 2>/dev/null || true; wait "$QEMU_PID" 2>/dev/null || true; ip link del "$TAP" 2>/dev/null || true; rm -f "$LOG" "$MON"' EXIT

CURL=(curl -s --max-time 3 -o /dev/null --interface 10.0.2.32 \
  --connect-to "$NAME:443:10.0.2.15:443")
[[ -s "$B/ca.pem" ]] && CURL+=(--cacert "$B/ca.pem")
up=
for _ in $(seq 1 40); do
  if "\${CURL[@]}" "https://$NAME/"; then up=1; break; fi
  sleep 0.25
done
if [[ -z "$up" ]]; then
  echo "FAIL: guest not answering over TAP before reboot probe"
  cat "$LOG"
  exit 1
fi

python3 "$repo_root/test_syn_cookie_reboot.py"
