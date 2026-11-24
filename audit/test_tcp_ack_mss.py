#!/usr/bin/env python3
"""Local TAP tests for ACK-window handling and peer-MSS enforcement.

Usage: test_tcp_ack_mss.py TARGET [expect|reject|wrap-expect|wrap-reject]
The tests use raw synthetic TCP segments to the QEMU guest only.
"""
from __future__ import annotations

import os
import select
import socket
import struct
import sys
import time
from pathlib import Path

if len(sys.argv) not in (2, 3):
    raise SystemExit("usage: test_tcp_ack_mss.py TARGET [expect|reject|wrap-expect|wrap-reject]")

mode = sys.argv[2] if len(sys.argv) == 3 else "expect"
if mode not in {"expect", "reject", "wrap-expect", "wrap-reject"}:
    raise SystemExit("mode must be expect, reject, wrap-expect or wrap-reject")

WRAP_MODE = mode.startswith("wrap-")
EXPECT_ACCEPT = mode in {"expect", "wrap-expect"}

GUEST_IP = socket.inet_aton("10.0.2.15")
HOST_IP = socket.inet_aton("10.64.0.1")
TAP = os.environ.get("TAP", "k2t")
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
sock.bind((TAP, 0))
host_mac = sock.getsockname()[4]
broadcast = b"\xff" * 6
HTTP = b"GET / HTTP/1.1\r\nHost: k15\r\nConnection: close\r\n\r\n"
REPLAY_HTTP = b"GET / HTTP/1.1\r\nHost: k15\r\nX-Replay-Probe: 0123456789abcdef0123456789abcdef\r\nConnection: close\r\n\r\n"


def checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def make_frame(
    sport: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes = b"",
    options: bytes = b"",
) -> bytes:
    if len(options) % 4:
        options += b"\x01" * (4 - len(options) % 4)
    offset = 20 + len(options)
    offset_flags = ((offset // 4) << 12) | flags
    tcp = struct.pack(
        "!HHIIHHHH",
        sport,
        80,
        seq & 0xFFFFFFFF,
        ack & 0xFFFFFFFF,
        offset_flags,
        65535,
        0,
        0,
    ) + options
    pseudo = HOST_IP + GUEST_IP + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    tcp_sum = checksum(pseudo + tcp + payload)
    tcp = tcp[:16] + struct.pack("!H", tcp_sum) + tcp[18:]
    total = 20 + len(tcp) + len(payload)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0x5151, 0, 64, 6, 0, HOST_IP, GUEST_IP)
    ip_sum = checksum(ip)
    ip = ip[:10] + struct.pack("!H", ip_sum) + ip[12:]
    return broadcast + host_mac + b"\x08\x00" + ip + tcp + payload


def parse_response(frame: bytes, sport: int):
    if len(frame) < 54 or frame[12:14] != b"\x08\x00":
        return None
    if frame[23] != 6 or frame[26:30] != GUEST_IP or frame[30:34] != HOST_IP:
        return None
    total = int.from_bytes(frame[16:18], "big")
    ihl = (frame[14] & 15) * 4
    tcp = 14 + ihl
    if len(frame) < tcp + 20 or total < ihl + 20:
        return None
    if int.from_bytes(frame[tcp : tcp + 2], "big") != 80:
        return None
    if int.from_bytes(frame[tcp + 2 : tcp + 4], "big") != sport:
        return None
    thl = (frame[tcp + 12] >> 4) * 4
    if thl < 20 or total < ihl + thl:
        return None
    end = min(len(frame), 14 + total)
    return {
        "seq": int.from_bytes(frame[tcp + 4 : tcp + 8], "big"),
        "ack": int.from_bytes(frame[tcp + 8 : tcp + 12], "big"),
        "flags": frame[tcp + 13],
        "options": frame[tcp + 20 : tcp + thl],
        "payload": frame[tcp + thl : end],
    }


def receive(sport: int, timeout: float = 1.5, want_payload: bool = False):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ready, _, _ = select.select([sock], [], [], max(0, deadline - time.monotonic()))
        if not ready:
            break
        item = parse_response(sock.recv(65536), sport)
        if item is None:
            continue
        if want_payload and not item["payload"]:
            continue
        return item
    return None


def handshake(sport: int, client_isn: int, mss: int):
    syn_options = b"\x02\x04" + struct.pack("!H", mss)
    sock.send(make_frame(sport, client_isn, 0, 0x02, options=syn_options))
    synack = receive(sport, 2.0)
    if synack is None or (synack["flags"] & 0x12) != 0x12:
        return None
    return synack


def parse_mss(options: bytes):
    i = 0
    while i < len(options):
        kind = options[i]
        if kind == 0:
            break
        if kind == 1:
            i += 1
            continue
        if i + 1 >= len(options):
            break
        size = options[i + 1]
        if size < 2 or i + size > len(options):
            break
        if kind == 2 and size == 4:
            return int.from_bytes(options[i + 2 : i + 4], "big")
        i += size
    return None


def fetch_after_handshake(
    sport: int, client_isn: int, synack, bad_ack: bool = False,
    request: bytes = HTTP, ack_delta: int | None = None
):
    server_next = (synack["seq"] + 1) & 0xFFFFFFFF
    client_next = (client_isn + 1) & 0xFFFFFFFF
    sock.send(make_frame(sport, client_next, server_next, 0x10))
    ack = (server_next + 0x10000) & 0xFFFFFFFF if bad_ack else server_next
    if ack_delta is not None:
        ack = (server_next + ack_delta) & 0xFFFFFFFF
    sock.send(make_frame(sport, client_next, ack, 0x18, request))
    deadline = time.monotonic() + 2.0
    payloads = []
    while time.monotonic() < deadline:
        item = receive(sport, max(0.01, deadline - time.monotonic()), want_payload=True)
        if item is None:
            break
        payloads.append(item["payload"])
        if b"HTTP/1." in b"".join(payloads):
            break
    return payloads


def report(label: str, observed: bool, detail: str, expected: bool = True) -> None:
    if observed != expected:
        expectation = "accept" if expected else "reject"
        raise SystemExit(f"FAIL: {label}: expected {expectation}; {detail}")
    print(f"PASS: {label}: {detail}")


def test_bad_ack() -> None:
    sport, isn = 52001, 0x12345678
    synack = handshake(sport, isn, 536)
    if synack is None:
        raise SystemExit("FAIL: no SYN-ACK for ACK-window control connection")
    server_next = (synack["seq"] + 1) & 0xFFFFFFFF
    if WRAP_MODE:
        print(f"OBSERVED: forced-wrap server ISS=0x{synack['seq']:08x}, SND.NXT=0x{server_next:08x}")
        if server_next < 0xFFFF0000:
            raise SystemExit(f"FAIL: forced-wrap image did not place SND.NXT near 2^32: 0x{server_next:08x}")
    payloads = fetch_after_handshake(sport, isn, synack, bad_ack=True)
    response = b"".join(payloads)
    report(
        "ACK-window test",
        response.startswith(b"HTTP/1."),
        "HTTP response received after an ACK beyond server SND.NXT"
        if response.startswith(b"HTTP/1.")
        else f"no HTTP response; captured {len(response)} payload bytes",
        expected=EXPECT_ACCEPT,
    )






def test_mss_boundary_matrix() -> None:
    for index, peer_mss in enumerate((0, 1, 179, 180, 181, 215, 216)):
        sport = 52200 + index
        isn = 0x56780000 + index
        synack = handshake(sport, isn, peer_mss)
        accepted = synack is not None and (synack["flags"] & 0x12) == 0x12
        if EXPECT_ACCEPT and not accepted:
            raise SystemExit(f"FAIL: bounty unexpectedly rejected peer MSS={peer_mss}")
        if not accepted:
            print(f"PASS: peer MSS={peer_mss}: SYN rejected")
            continue
        advertised = parse_mss(synack["options"])
        payloads = fetch_after_handshake(sport, isn, synack, bad_ack=False)
        response = b"".join(payloads)
        if (EXPECT_ACCEPT or peer_mss >= 216) and not response.startswith(b"HTTP/1."):
            raise SystemExit(f"FAIL: peer MSS={peer_mss}: accepted control SYN but no HTTP response")
        maximum = max((len(payload) for payload in payloads), default=0)
        observed_violation = maximum > peer_mss
        expected_violation = EXPECT_ACCEPT and peer_mss < 180
        if observed_violation != expected_violation:
            raise SystemExit(
                f"FAIL: peer MSS={peer_mss}: oversized segment observed={observed_violation}, "
                f"expected={expected_violation} (largest={maximum})"
            )
        print(
            f"PASS: peer MSS={peer_mss}, SYN-ACK MSS={advertised}, "
            f"largest outbound TCP payload={maximum}"
        )


def test_delayed_syn_cookie() -> None:
    # A SYN cookie without a time bucket should remain valid after the SYN
    # retransmission cache has aged out. No ACK is sent until after the delay.
    sport, isn = 52003, 0x3456789A
    synack = handshake(sport, isn, 536)
    if synack is None:
        raise SystemExit("FAIL: no SYN-ACK for delayed SYN-cookie control SYN")
    delay = 65
    print(f"OBSERVED: holding the synthetic SYN-ACK for {delay}s before its first ACK")
    time.sleep(delay)
    payloads = fetch_after_handshake(sport, isn, synack, bad_ack=False)
    response = b"".join(payloads)
    report(
        "delayed SYN-cookie test",
        response.startswith(b"HTTP/1."),
        f"the ACK was accepted after {delay}s and the HTTP request was processed"
        if response.startswith(b"HTTP/1.")
        else f"no HTTP response after {delay}s; captured {len(response)} payload bytes",
        expected=True,
    )





def exchange_and_close(sport: int, client_seq: int, server_seq: int, request: bytes = HTTP):
    # Materialize the cookie-backed slot, send one HTTP request, then close it
    # with a sequence-valid FIN. Fall back to RST if the peer does not FIN back.
    sock.send(make_frame(sport, client_seq, server_seq, 0x10))
    sock.send(make_frame(sport, client_seq, server_seq, 0x18, request))
    client_after_request = (client_seq + len(request)) & 0xFFFFFFFF
    client_ack = client_after_request
    response = bytearray()
    server_next = server_seq
    fin_seen = False
    deadline = time.monotonic() + 4.0
    while time.monotonic() < deadline:
        item = receive(sport, min(0.5, max(0.01, deadline - time.monotonic())))
        if item is None:
            if response:
                break
            continue
        if item["seq"] != server_next:
            continue
        client_ack = item["ack"]
        payload = item["payload"]
        response.extend(payload)
        server_next = (server_next + len(payload)) & 0xFFFFFFFF
        if item["flags"] & 0x01:
            server_next = (server_next + 1) & 0xFFFFFFFF
            fin_seen = True
        if payload or item["flags"] & 0x01:
            sock.send(make_frame(sport, client_ack, server_next, 0x10))

    if not response.startswith(b"HTTP/1."):
        return bytes(response), False, client_ack, False

    # If the response did not already carry FIN, a client FIN asks the server
    # to close its side too.
    client_after_fin = (client_ack + 1) & 0xFFFFFFFF
    deadline = time.monotonic() + 2.0
    if not fin_seen:
        sock.send(make_frame(sport, client_ack, server_next, 0x11))
    while not fin_seen and time.monotonic() < deadline:
        item = receive(sport, min(0.5, max(0.01, deadline - time.monotonic())))
        if item is None:
            continue
        if item["seq"] != server_next:
            continue
        payload = item["payload"]
        server_next = (server_next + len(payload)) & 0xFFFFFFFF
        if item["flags"] & 0x01:
            server_next = (server_next + 1) & 0xFFFFFFFF
            fin_seen = True
        if payload or fin_seen:
            sock.send(make_frame(sport, client_after_fin, server_next, 0x10))
        if fin_seen:
            break

    if not fin_seen:
        # If the peer does not finish the close, reset at its current expected sequence.
        sock.send(make_frame(sport, client_after_fin, server_next, 0x14))
    time.sleep(0.2)
    print(
        f"OBSERVED: teardown request={request[:4]!r}, peer_ack=0x{client_ack:08x}, "
        f"client_next=0x{client_after_request:08x}, fin_seen={fin_seen}, "
        f"reset_fallback={not fin_seen}"
    )
    return bytes(response), True, client_ack, fin_seen


def test_cookie_replay_after_teardown() -> None:
    sport, isn = 52004, 0x456789AB
    synack = handshake(sport, isn, 536)
    if synack is None:
        print("OBSERVED: cookie replay after teardown: no SYN-ACK for control SYN")
        return

    client_seq = (isn + 1) & 0xFFFFFFFF
    original_server_ack = (synack["seq"] + 1) & 0xFFFFFFFF
    first_response, first_teardown, first_peer_ack, first_fin = exchange_and_close(
        sport, client_seq, original_server_ack
    )
    if not first_response.startswith(b"HTTP/1.") or not first_teardown or not first_fin:
        print(
            "OBSERVED: cookie replay after teardown: could not establish the "
            f"initial HTTP exchange and reset (response={len(first_response)} bytes)"
        )
        return

    # Keep the exact cookie for 65 seconds after a completed FIN close, then
    # replay it and send a fresh request at the old sequence.
    drain_deadline = time.monotonic() + 0.25
    while time.monotonic() < drain_deadline:
        receive(sport, timeout=min(0.05, drain_deadline - time.monotonic()))
    replay_delay = 65
    time.sleep(replay_delay)
    second_response, second_teardown, replay_peer_ack, replay_fin = exchange_and_close(
        sport, client_seq, original_server_ack, REPLAY_HTTP
    )
    accepted = second_response.startswith(b"HTTP/1.")
    expected_replay_ack = (client_seq + len(REPLAY_HTTP)) & 0xFFFFFFFF
    distinct_request = accepted and replay_peer_ack == expected_replay_ack
    replay_status = second_response.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
    print(
        "OBSERVED: cookie ACK replay after RST teardown: "
        f"first_http={first_response.startswith(b'HTTP/1.')}, "
        f"first_fin_close={first_fin}, replay_delay_s={replay_delay}, replay_http={accepted}, "
        f"replay_ack_matches_new_request={distinct_request}, replay_peer_ack=0x{replay_peer_ack:08x}, "
        f"expected_replay_ack=0x{expected_replay_ack:08x}, first_peer_ack=0x{first_peer_ack:08x}, "
        f"replay_status={replay_status!r}, replay_response_bytes={len(second_response)}, "
        f"replay_fin_close={replay_fin}, replay_teardown_sent={second_teardown}, "
        f"original_cookie_ack=0x{original_server_ack:08x}"
    )


def test_ack_boundary_matrix() -> None:
    for index, delta in enumerate((1, 63, 64, 0xFFFF, 0x10000)):
        sport = 52100 + index
        isn = 0x45670000 + index
        synack = handshake(sport, isn, 536)
        if synack is None:
            raise SystemExit(f"FAIL: no SYN-ACK for ACK delta +{delta} control connection")
        server_next = (synack["seq"] + 1) & 0xFFFFFFFF
        if WRAP_MODE:
            print(f"OBSERVED: ACK boundary server SND.NXT=0x{server_next:08x}")
            if server_next < 0xFFFF0000:
                raise SystemExit(f"FAIL: forced-wrap SND.NXT not near 2^32: 0x{server_next:08x}")
        payloads = fetch_after_handshake(
            sport, isn, synack, bad_ack=False, ack_delta=delta
        )
        response = b"".join(payloads)
        observed = response.startswith(b"HTTP/1.")
        result = "HTTP processed" if observed else "no HTTP payload"
        if observed != EXPECT_ACCEPT:
            raise SystemExit(
                f"FAIL: ACK delta +{delta} beyond SND.NXT: {result}; "
                f"expected accept={EXPECT_ACCEPT}"
            )
        print(f"PASS: ACK delta +{delta} beyond SND.NXT: {result}")



def test_small_mss() -> None:
    sport, isn, peer_mss = 52002, 0x23456789, 100
    synack = handshake(sport, isn, peer_mss)
    if synack is None:
        report("MSS=100 test", False, "guest sent no SYN-ACK", expected=EXPECT_ACCEPT)
        return
    advertised = parse_mss(synack["options"])
    payloads = fetch_after_handshake(sport, isn, synack, bad_ack=False)
    maximum = max((len(p) for p in payloads), default=0)
    report(
        "MSS=100 test",
        maximum > peer_mss,
        f"peer MSS={peer_mss}, SYN-ACK MSS={advertised}, largest outbound data segment={maximum}",
        expected=EXPECT_ACCEPT,
    )


if __name__ == "__main__":
    try:
        test_bad_ack()
        test_ack_boundary_matrix()
        if not WRAP_MODE:
            test_small_mss()
            test_mss_boundary_matrix()
            test_delayed_syn_cookie()
            test_cookie_replay_after_teardown()
        print(f"RESULT: TCP ACK/MSS probes completed in mode={mode}")
    finally:
        sock.close()
