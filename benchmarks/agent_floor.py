"""Agent-floor probe: raw UDP exchange with a pre-encoded v2c GET.

No library code, no encode/decode — measures snmpd + loopback + syscalls,
the cost every client pays identically. This is the floor to subtract
from wall-clock per-request numbers.
"""

import socket
import time

DATA = bytes.fromhex(
    "302702010104067075626c6963a01a0202044d020100020100300e300c06082b060102010103000500"
)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(2.0)
sock.sendto(DATA, ("127.0.0.1", 1199))
resp = sock.recv(4096)
print(f"sanity: {len(resp)}-byte response received")

n = 500
t0 = time.perf_counter()
for _ in range(n):
    sock.sendto(DATA, ("127.0.0.1", 1199))
    sock.recv(4096)
dt = time.perf_counter() - t0
print(
    f"agent-floor: {n} raw exchanges in {dt:.3}s "
    f"-> {dt / n * 1e6:.1f} us/exchange"
)
