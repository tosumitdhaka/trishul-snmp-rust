# trishul-snmp (tsnmp)

A native Rust SNMP toolkit — manager, notifier, listener, and read-only responder for
SNMPv1/v2c/v3 (USM), with optional compiled-JSON MIB enrichment.

- **Crate**: `trishul-snmp` · **Binary**: `tsnmp` · **License**: MIT · **MSRV**: 1.88
- Rust port of the Python `trishul-snmp` reference implementation
  (`/home/dhaka/trishul/trishul-snmp`). The Python library is the reference for the
  *feature surface*; the API shape here is Rust-native.
- **Status**: Phase 8 (CLI + release prep) complete — the 11-subcommand `tsnmp`
  binary, user docs, and publish metadata are in place.

## Goal

Deliver the Python reference's complete feature surface as an idiomatic, async-first
Rust runtime: manager operations (get / getnext / getbulk / walk / bulkwalk) over
v1/v2c/v3-USM, notification send and listen across all three security models, offline
notification decode, a narrow read-only v2c responder/simulator, and optional
compiled-JSON MIB enrichment produced by `trishul-smi` (tsmi) — with a live-snmpd
conformance gate as the interop proof.

## Feature surface

| Area | Coverage |
|---|---|
| Versions | SNMPv1, v2c, v3-USM (auth: MD5, SHA-1, SHA-224/256/384/512; priv: AES-128/192/256-CFB, 3DES-EDE) |
| Manager | GET, GETNEXT, GETBULK (V1: transparent GETNEXT downgrade), walk, bulkwalk |
| v3 machinery | engine discovery, engine-time window adoption, single-retry recovery from `usmStatsNotInTimeWindows` |
| Notifications | v1/v2c/v3 trap send; inform send with retry; v1/v2c/v3 listeners with replay guard and drop taxonomy; offline decode |
| Responder | read-only v2c responder/simulator (GET/GETNEXT/GETBULK, `noSuchObject`/`endOfMibView` synthesis, GETBULK truncation) |
| MIB | consumer of tsmi compiled-JSON bundles (schema ≤ 1.1): symbol resolution, OID lookup, enum/BITS/units enrichment |

## Non-goals

- No SET operation (reference has none; responder answers `notWritable`)
- No DES-CBC privacy (reference fails fast on it)
- No MIB parsing/compiling — tsmi owns that; this crate consumes its JSON bundles
- No sync API (reference is async-only; parity)
- No full agent framework, no TLS/DTLS, no FIPS mode

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — goal, module tree, public API design,
  error taxonomy, test seams, and deliberate deviations from the Python reference
- [`docs/plan.md`](docs/plan.md) — phased implementation plan with verification gates,
  test architecture, and risk register
- [`docs/cli.md`](docs/cli.md) — CLI reference: every subcommand, flag, exit code, and
  output mode

## CLI usage

The `tsnmp` binary covers SNMPv1, SNMPv2c, and SNMPv3 for polling, notification
send/listen, and offline decode. Full option tables live in
[`docs/cli.md`](docs/cli.md).

```bash
# Build
cargo build --release

# Version
tsnmp version

# Polling (v1/v2c/v3): get, getnext, getbulk, walk, bulkwalk
tsnmp get --host 10.0.0.10 1.3.6.1.2.1.1.3.0
tsnmp get --host 10.0.0.10 --bundle ./IF-MIB.json IF-MIB::ifDescr.1
tsnmp get --host 10.0.0.10 --snmp-version 3 --username monitor \
  --auth-protocol sha256 --auth-key-env TSNMP_AUTH 1.3.6.1.2.1.1.3.0
tsnmp walk --host 10.0.0.10 1.3.6.1.2.1.2.2
tsnmp bulkwalk --host 10.0.0.10 --max-repetitions 25 1.3.6.1.2.1.2.2

# Notifications
tsnmp trap --host 10.0.0.20 1.3.6.1.6.3.1.1.5.3
tsnmp trap --host 10.0.0.20 --snmp-version 3 --username notify \
  --local-engine-id 8000010203 --local-engine-boots 7 --local-engine-time 99 \
  1.3.6.1.6.3.1.1.5.3
tsnmp inform --host 10.0.0.20 1.3.6.1.6.3.1.1.5.3
tsnmp listen --host 127.0.0.1 --port 9162 --count 1
tsnmp listen --snmp-version 3 --username notify \
  --local-engine-id 8000010203 --local-engine-boots 7 --local-engine-time 99

# Offline decode and translation
tsnmp decode-notification --hex 302602010104067075626c6963...
tsnmp translate --bundle ./IF-MIB.json IF-MIB::ifDescr.1
```

Secrets: `--auth-key-env TSNMP_AUTH` names an environment variable whose value
is the passphrase — the secret never appears on the command line.

Output defaults to line-oriented text (`NAME = VALUE`); `--json` switches to
machine-readable JSON, and `--numeric` forces numeric OIDs even when a bundle
is loaded.

Exit codes: `0` success, `1` runtime/translation/protocol failure or non-zero
SNMP error status, `2` invalid CLI usage.

## Ecosystem position

```
trishul-smi (tsmi)          trishul-snmp (tsnmp)           trishul-snmp (Python)
MIB compiler ──JSON────▶  Rust SNMP runtime   ◄──feature parity──  reference implementation
```

The compiled-JSON bundle format is a language-agnostic contract: the same fixture
bundles validate both implementations.
