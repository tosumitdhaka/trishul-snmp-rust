# trishul-snmp (tsnmp)

A native Rust SNMP toolkit — manager, notifier, listener, and read-only responder for
SNMPv1/v2c/v3 (USM), with optional compiled-JSON MIB enrichment.

- **Crate**: `trishul-snmp` · **Binary**: `tsnmp` · **License**: MIT · **MSRV**: 1.88
- Rust port of the Python `trishul-snmp` reference implementation
  (`/home/dhaka/trishul/trishul-snmp`). The Python library is the reference for the
  *feature surface*; the API shape here is Rust-native.
- **Status**: Phase 0 complete (skeleton, CI, fixtures, docs); Phase 1 (codec core)
  reviewed and greenlit. Architecture and plan are finalized (see docs below) and
  independently reviewed.

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

## Ecosystem position

```
trishul-smi (tsmi)          trishul-snmp (tsnmp)           trishul-snmp (Python)
MIB compiler ──JSON────▶  Rust SNMP runtime   ◄──feature parity──  reference implementation
```

The compiled-JSON bundle format is a language-agnostic contract: the same fixture
bundles validate both implementations.
