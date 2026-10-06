# Benchmarks: tsnmp-r vs the Python reference

Measured 2026-10-06, comparing **trishul-snmp 0.1.0 (Rust, cargo-installed,
release build)** against the **Python reference `trishul-snmp` (venv)**, same
machine, same agent, same OIDs. Reproduction scripts: `benchmarks/`.

## Environment

| | |
|---|---|
| OS | WSL2 (Linux 6.6.114), x86_64 |
| Agent | net-snmpd 5.9.4.pre2, `127.0.0.1:1199`, community `public`, ~10.3k OIDs under `1.3.6.1.2.1` |
| Rust side | `cargo install trishul-snmp --locked` (toolchain 1.95) |
| Python side | Python 3.12.3, reference checkout in a venv (zero required deps) |
| Timing | `time.perf_counter()` around full processes (CLI) or in-process loops (library); medians of N after warmup unless noted |

## CLI level (full process: startup + connect + query)

| Workload | Rust | Python | Ratio |
|---|---|---|---|
| `get sysDescr.0` (median of 30) | **1.39 ms** | 95.69 ms | ~69× |
| `walk system` ~37 OIDs (median of 10) | **1.95 ms** | 101.26 ms | ~52× |
| `bulkwalk system` (median of 10) | **1.89 ms** | 97.67 ms | ~52× |
| `walk mib-2` 10,345 OIDs (median of 3) | **140.81 ms** | 412.13 ms | ~2.9× |

The single-query gap is dominated by process startup: Python's interpreter +
import cost is ~90 ms per invocation (`tsnmp version` ≈ 90 ms vs <5 ms).

## Library level (in-process, startup excluded)

| Workload | Rust | Python | Ratio |
|---|---|---|---|
| 200 sequential GETs | **130 µs/req** (7,712 req/s) | 185 µs/req (5,401 req/s) | 1.43× |
| `walk` mib-2 (single run) | **0.176 s** (~59k varbinds/s) | 0.315 s (~33k varbinds/s) | 1.8× |

## Why the per-request ratio is 1.43× — decomposition

The agent floor (raw UDP exchange of a pre-encoded GET, no library code,
median of 500) is **101.6 µs** — the cost both clients pay identically.

| | Rust | Python |
|---|---|---|
| Wall clock per GET | 130 µs | 185 µs |
| Agent floor (shared) | 101.6 µs | 101.6 µs |
| **Client-side slice** | **~28 µs** | **~83 µs** → **~2.9×** |

snmpd caps any client at ~9,800 req/s on this loopback; Rust ran at 79% of
the ceiling, Python at 55%. On a real network (ms-scale RTT) both clients
converge for single requests — the port's structural wins are startup,
walk throughput, codec CPU, and memory, not per-request latency.

## Codec-only microbench (pure CPU, no network)

50,000 decodes of the same golden v2c GET datagram:

| | per decode |
|---|---|
| Rust | **0.392 µs** |
| Python | 9.171 µs |

**23.4×.** The Python decoder is pure Python (no compiled backend).

## Resource usage (CLI `walk mib-2`, `/usr/bin/time -v`)

| Metric | Rust | Python | Ratio |
|---|---|---|---|
| Max RSS | **9.8 MB** | 30.4 MB | 3.1× |
| User CPU | **0.03 s** | 0.36 s | 12× |
| System CPU | 0.05 s | 0.05 s | 1.0× |
| Wall clock | 0.26 s | 0.49 s | 1.9× |

## Footprint

| | Rust | Python |
|---|---|---|
| Library LOC | 18,830 (46 files) | 9,155 (42 files) |
| Test LOC / functions | 15,413 / 699 | 17,786 / 653 |
| Required runtime deps | 0 (compiled in) | 0 (pure Python) |
| v3 crypto | built-in (RustCrypto) | optional `cryptography` (15 MB installed) |
| Shipped artifact | 3.6 MB self-contained binary | 1.0 MB source + interpreter + venv |

## Caveats

- WSL2 loopback; snmpd itself is the shared bottleneck — absolute numbers
  will differ on other hosts, ratios less so.
- Library-walk and resource numbers are single-run; CLI numbers are
  medians. Varbind counts varied 10,338–10,345 between runs (live
  `tcpConnTable`/`udpTable` churn).
- The floor subtraction is an estimate (the raw probe carries its own small
  loop overhead); direction and magnitude solid, decimals not gospel.
