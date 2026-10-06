# Benchmarks

Reproducible performance comparison of tsnmp-r against the Python reference
(`trishul-snmp`). Results and analysis: `docs/benchmarks.md`.

## Layout

| Path | What it measures |
|---|---|
| `bench-snmpd.conf` | Minimal agent config (127.0.0.1:1199, community `public`) |
| `bench_cli.py` | CLI-level: full-process time per subcommand (median of N, warmed) |
| `bench_py_lib.py` | Python reference, in-process: 200 sequential GETs + one mib-2 walk |
| `tsnmp-bench/` | Rust crate (depends on published `trishul-snmp` from crates.io): same library-level workloads |
| `tsnmp-bench/src/bin/codec_bench.rs` | Rust BER decode microbench (50k decodes of a golden v2c GET) |
| `codec_bench_py.py` | Python reference BER decode microbench (same datagram, same count) |
| `agent_floor.py` | Agent floor: raw UDP exchange of a pre-encoded GET, no library code |

`tsnmp-bench/Cargo.toml` pins `trishul-snmp` from crates.io (the version
measured was 0.1.0) — adjust when re-running against a newer release.

## Running

1. Start the agent (adjust paths to your snmpd):

   ```sh
   setsid snmpd -f -c benchmarks/bench-snmpd.conf -Lo /tmp/bench-snmpd.log \
       >/dev/null 2>&1 < /dev/null &
   ```

2. CLI-level (adjust the two binary paths at the top of the script first):

   ```sh
   python3 benchmarks/bench_cli.py
   ```

3. Library-level (adjust the interpreter/venv path to the Python reference):

   ```sh
   python3 benchmarks/bench_py_lib.py          # Python side
   cargo run --release --manifest-path benchmarks/tsnmp-bench/Cargo.toml  # Rust side
   ```

4. Codec microbench:

   ```sh
   python3 benchmarks/codec_bench_py.py
   cargo run --release --manifest-path benchmarks/tsnmp-bench/Cargo.toml \
       --bin codec_bench
   ```

5. Agent floor:

   ```sh
   python3 benchmarks/agent_floor.py
   ```

Resource usage (RSS/CPU) via `/usr/bin/time -v <cmd>` around the same
`walk 1.3.6.1.2.1` invocation, both CLIs.
