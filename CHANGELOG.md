# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-10-06

### Added

- **`tsnmp` alias crate**: `tsnmp` and `trishul-snmp` on crates.io are the
  same project — both names resolve to this toolkit and both install the
  same `tsnmp` CLI binary. Published in lockstep; the canonical name
  remains `trishul-snmp`.

- **Ergonomic root re-exports**: `Manager`, `V1Config`, `V2cConfig`, `V3Config`,
  `WalkOptions`, `Error`, `Oid`, `SnmpValue`, `VarBind`, `Target`, `MibBundle`,
  `ListenerConfig`, `Notifier`, `NotificationListener`, `decode_notification`,
  and `SnmpResponder` are importable directly from the crate root
  (`use trishul_snmp::Manager`). The full module paths remain valid.
- **Benchmarks**: reproducible comparison scripts against the Python reference
  (CLI-level, library-level, agent-floor decomposition, codec microbench,
  resource usage) under `benchmarks/`, with the measured results documented in
  `docs/benchmarks.md`.
- **Amortized-O(1) replay-guard engine LRU**: the v3 notification listener's
  engine recency tracking now uses lazy tombstones (a touched engine pushes a
  fresh recency entry; superseded entries are compacted once the dead count
  reaches the live bound) instead of an O(cap) scan + `VecDeque::remove` under
  the guard mutex per datagram. Eviction order and first-seen re-adoption
  semantics are unchanged.
- **Responder panic observability**: `SnmpResponder::recent_panics()` drains the
  payload texts of the most recent handler panics (bounded at 32, oldest
  dropped), pairing the existing `panic_count()` with *what* panicked.
- **authPriv send coverage**: full-path v3 authPriv INFORM and trap send
  round-trips (our `Notifier` → our `V3NotificationListener` on loopback:
  encode + AES-128-CFB encrypt + MD5 auth, verify + decrypt + auto-ack),
  closing the Phase-4 parity gap for authPriv SEND tests.
- **Cargo examples**: `examples/get.rs`, `examples/walk.rs`, and
  `examples/listen.rs` — runnable v2c GET / subtree walk / one-trap listen
  programs, documented against the repo's `benchmarks/bench-snmpd.conf` agent.
- **Cross-platform CI**: the test job now runs on ubuntu, macOS, and Windows
  (formatting/clippy/docs/MSRV stay ubuntu-only). The OS-specific code paths
  (`SystemRng` entropy source, unix-only `~user` bundle-path expansion and
  symlink-containment tests) are cfg-gated; the conformance suite remains
  env-gated and self-skips where `snmpd` is unavailable.

### Fixed

- The 0.1.0 entry documented the import path `trishul_snmp::Manager`, which did
  not resolve in 0.1.0; the root re-exports above make that path real.

## [0.1.0] - 2026-10-06

### Added

- **Manager** (`trishul_snmp::Manager`): SNMPv1, v2c, and v3-USM connections with
  GET, GETNEXT, GETBULK, `walk`, and `bulkwalk`. V1 requests transparently
  downgrade GETBULK to GETNEXT. v3 includes engine discovery, engine-time
  window adoption, and single-retry recovery from `usmStatsNotInTimeWindows`
  REPORTs.
- **Notifications** (`trishul_snmp::notify`): trap send across every
  cross-version combination (v1, v2c, and v3-USM traps; v3 informs with
  retry), plus v1/v2c and v3 notification listeners with a replay guard and a
  nine-reason drop taxonomy (`DropCounts`). Offline decode of captured
  notification datagrams (`decode_notification`).
- **Read-only responder** (`trishul_snmp::responder`): a v1/v2c/v3 responder
  and simulator answering GET/GETNEXT/GETBULK with
  `noSuchObject`/`endOfMibView` synthesis and GETBULK response truncation;
  SET is rejected (v1 `readOnly`, v2c/v3 `notWritable`).
- **MIB bundles** (`trishul_snmp::mib`): consumer of tsmi compiled-JSON bundles
  (schema ≤ 1.1) with symbol resolution, OID lookup, search, and
  enum/BITS/units enrichment for manager, notifier, and listener output.
- **CLI** (`tsnmp`): 11 subcommands — `translate`, `get`, `getnext`, `getbulk`,
  `walk`, `bulkwalk`, `trap`, `inform`, `listen`, `decode-notification`, and
  `version` — with text/JSON output and secrets passed via environment
  variables instead of the command line.

### Security

- **USM authentication and privacy**: MD5, SHA-1, and the SHA-2 family
  (SHA-224/256/384/512) HMAC authentication; AES-128/192/256-CFB and 3DES-EDE
  privacy. DES-CBC is intentionally unsupported.
- **Bounded replay-guard engine tracking**: the v3 notification listener's
  replay guard tracks at most 1024 distinct engine IDs (LRU); a listener
  hearing many distinct engine IDs cannot grow its per-engine state without
  bound.
- **Symlink-safe manifest containment**: MIB bundle manifests are resolved
  through symlinks and rejected when an entry points outside the bundle
  directory.