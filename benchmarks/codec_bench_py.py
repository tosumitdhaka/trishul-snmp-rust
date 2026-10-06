"""Codec-only microbench: Python reference decode of a golden v2c GET."""

import sys
import time

sys.path.insert(0, "/home/dhaka/trishul/trishul-snmp")
from trishul_snmp.wire.message import decode_message

DATA = bytes.fromhex(
    "302702010104067075626c6963a01a0202044d020100020100300e300c06082b060102010103000500"
)

m = decode_message(DATA)
assert m.version == 1  # v2c on the wire

n = 50_000
for _ in range(1_000):  # warmup
    decode_message(DATA)

t0 = time.perf_counter()
for _ in range(n):
    decode_message(DATA)
dt = time.perf_counter() - t0
print(f"py-codec: {n} decodes in {dt:.3f}s -> {dt / n * 1e6:.3f} us/decode")
