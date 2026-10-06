# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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