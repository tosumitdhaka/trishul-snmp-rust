"""CLI-level benchmark: tsnmp (Rust, cargo-installed) vs tsnmp (Python venv).

Full-process timing (startup + connect + query) — the user-visible CLI cost.
Same agent (snmpd 5.9.4.pre2 @ 127.0.0.1:1199), same OIDs, warmup first.
"""

import statistics
import subprocess
import sys
import time

RUST = ["/home/dhaka/.cargo/bin/tsnmp"]
PY = ["/home/dhaka/trishul/trishul-snmp/.venv/bin/tsnmp"]
CONN = ["--host", "127.0.0.1", "--port", "1199", "--community", "public"]
OID_SYSDESCR = "1.3.6.1.2.1.1.1.0"
OID_SYSTEM = "1.3.6.1.2.1.1"
OID_MIB2 = "1.3.6.1.2.1"

WORKLOADS = [
    ("get sysDescr.0", ["get", *CONN, OID_SYSDESCR], 30),
    ("walk system (~37 oids)", ["walk", *CONN, OID_SYSTEM], 10),
    ("bulkwalk system (~37 oids)", ["bulkwalk", *CONN, OID_SYSTEM], 10),
]


def timed(cmd: list[str]) -> float:
    t0 = time.perf_counter()
    r = subprocess.run(cmd, capture_output=True, text=True)
    dt = time.perf_counter() - t0
    if r.returncode != 0:
        print(f"FAILED: {' '.join(cmd)}\n{r.stderr[:300]}", file=sys.stderr)
        sys.exit(1)
    return dt


def bench(label: str, cli: list[str], sub: list[str], n: int) -> list[float]:
    cmd = cli + sub
    for _ in range(2):  # warmup
        timed(cmd)
    return [timed(cmd) for _ in range(n)]


def report(label: str, times: list[float]) -> None:
    med = statistics.median(times) * 1000
    lo, hi = min(times) * 1000, max(times) * 1000
    print(f"{label:<24} median={med:8.2f} ms   min={lo:7.2f}   max={hi:8.2f}")


def main() -> None:
    results: dict[str, list[float]] = {}
    for cli_name, cli in (("rust", RUST), ("python", PY)):
        for label, sub, n in WORKLOADS:
            key = f"{cli_name:<7}| {label}"
            results[key] = bench(label, cli, sub, n)

    # one-off: size of the full mib-2 tree, then a big walk for each
    mib2_lines = subprocess.run(
        RUST + ["walk", *CONN, OID_MIB2], capture_output=True, text=True, check=True
    ).stdout.count("\n")
    print(f"# mib-2 walk size: {mib2_lines} varbinds\n")
    for cli_name, cli in (("rust", RUST), ("python", PY)):
        results[f"{cli_name:<7}| walk mib-2 ({mib2_lines} oids)"] = bench(
            "mib2", cli, ["walk", *CONN, OID_MIB2], 3
        )

    for key, times in results.items():
        report(key, times)


if __name__ == "__main__":
    main()
