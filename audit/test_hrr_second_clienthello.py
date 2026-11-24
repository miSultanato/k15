#!/usr/bin/env python3
"""Summarize an OpenSSL s_client HRR/second-ClientHello trace from local QEMU."""
from __future__ import annotations

import re
import sys
from pathlib import Path

if len(sys.argv) != 2:
    raise SystemExit("usage: test_hrr_second_clienthello.py OPENSSL_TRACE")

trace = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
flat = re.sub(r"[^0-9a-f]", "", trace.lower())
hrr_random = "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
client_hellos = [m.start() for m in re.finditer("ClientHello", trace)]
server_hellos = [m.start() for m in re.finditer("ServerHello", trace)]
hrr_match = re.search(r"cf[\s:]+21[\s:]+ad[\s:]+74[\s:]+e5[\s:]+9a[\s:]+61[\s:]+11", trace.lower())
hrr_present = hrr_random in flat
second_client_hello = len(client_hellos) >= 2 and hrr_match is not None and client_hellos[1] > hrr_match.start()
server_ccs = [m.start() for m in re.finditer(r"<<<[^\n]*ChangeCipherSpec", trace)]
final_server_hello = server_hellos[1] if len(server_hellos) >= 2 else -1
ccs_after_final_server_hello = final_server_hello >= 0 and any(p > final_server_hello for p in server_ccs)
http = "HTTP/1.1" in trace or "HTTP/1.0" in trace

print(
    "HRR trace: "
    f"hrr_random={hrr_present}, client_hellos={len(client_hellos)}, "
    f"second_client_hello_after_hrr={second_client_hello}, "
    f"server_hellos={len(server_hellos)}, server_ccs={len(server_ccs)}, "
    f"server_ccs_after_final_server_hello={ccs_after_final_server_hello}, "
    f"http_response={http}"
)
if not trace.strip():
    raise SystemExit("FAIL: OpenSSL produced an empty trace")
