# tsnmp Implementation Plan

Status: Phases 0–8 complete (bootstrap through CLI + release prep). All phase
gates green at HEAD; the Phase 8 gate (CLI subprocess tests, full conformance
matrix, MSRV check) is the release checkpoint. This document is the contract
the implementation is built and reviewed against.

## Verification philosophy

1. **Spec before implementation where interop matters most**: crypto-parity vectors
   (net-snmp localized keys, draft-reeder Appendix B) are merged *before* any
   `security/usm/priv.rs` code exists.
2. **Live snmpd is the conformance gate**: the reference's CI matrix (agents on
   127.0.0.1:1161/1162/1171/1173/1174, v3 user matrix) is reused as-is. Any
   cross-implementation byte or semantic mismatch blocks the phase.
3. **Tests target the spec, not the implementation**: hardening/quirk tests are
   written from the RFCs and the reference's behavior spec, so a wrong
   implementation cannot pass by defining its own truth.
4. **Determinism by construction**: injected Clock/RNG seams replace the reference's
   monkeypatching (`os.urandom`, loop patching — confirmed by grep in the study).

## Phases

| Phase | Scope | Deliverable | Verification gate | Go/No-Go checkpoint |
|---|---|---|---|---|
| **0 — bootstrap** | Cargo skeleton, CI (fmt/clippy/test + MSRV 1.88), fixtures vendored (crypto vectors, wire-golden, bundles, snmpd config), `tests/common` harness | green CI with stubs | CI green | — |
| **1 — codec core** | `types`, `error`, `codec` (rasn): Oid, SnmpValue (manual strict Decode, §5.3a), Pdu incl. v1 Trap + Report, v1/v2c message, DER-mode + remainder shim, `validate.rs` typed-side hardening, `locate_auth_params` | lib milestone 1 | property + wire tests green; golden 26/28 (the 2 v3 goldens gate in Phase 3 with USM auth); test split: 3 offset vectors from test_v3_wire.py now, its other 16 functions with `codec/v3` in Phase 3 | **rasn verdict (delivered Oct 2026: ora-3 review + 8/8 executable pins in tests/rasn_pins.rs)**: hybrid — rasn structure + manual strict value layer (~150 LOC); no fallback needed |
| **2 — v1/v2c runtime** | `transport`, `session`, `target.rs`, Community, `Manager` (get/getnext/getbulk, V1 downgrade, walk), `Notifier` v1/v2c | lib milestone 2 | loopback manager/walk/notify tests; snmpd conformance v1+v2c matrix green | end-to-end parity vs reference on the golden agent (walk of `system` subtree, varbind-equal) |
| **3 — v3 auth** | `codec/v3`, USM KDF + HMAC auth, engine discovery + recovery, v3 manager noPriv/authNoPriv | lib milestone 3 | crypto vectors merged first (locked); RFC 3414 A.2 + RFC 7860 tag lengths; snmpd authNoPriv users green | auth interop proven (snmpd SHA-256 authNoPriv round-trip) |
| **4 — v3 priv** | `priv.rs`: AES-128/192/256-CFB (Blumenthal derivation), 3DES-EDE (reeder chain, padding-lenient decrypt), salt rules; v3 inform/trap send | lib milestone 4 | snmpd full v3 matrix (all users incl. digest/key-length mismatch combos); net-snmp key vectors | priv interop proven; any cross-implementation byte mismatch blocks release |
| **5 — listeners** | v2c + v3 listeners (replay guard, drop taxonomy, discovery REPORT, inform ack), offline `decode_notification` | lib milestone 5 | loopback listener suites; snmpd coldStart trap + inform fixtures | — |
| **6 — MIB** | `mib/` (model, loader, registry, render), enrichment wiring into Manager/Notifier/Listener | lib milestone 6 | bundle fixtures load; enrichment output identical to Python on golden varbinds (enum/BITS/units) | fixture revision pin resolved (see risks) |
| **7 — responder** | `responder/` (BTreeMap source, simulation rules, GETBULK truncation) | lib milestone 7 | net-snmp `snmpget`/`snmpwalk` client tools against our responder (the reference does exactly this) | — |
| **8 — CLI + release** | `cli/` (clap args, secret-via-env flags `--auth-key-env`/`--priv-key-env VARNAME` as in the reference, output renderers), all 11 subcommands (translate, get, getnext, getbulk, walk, bulkwalk, trap, inform, listen, decode-notification, version), `tsnmp` bin, user docs, publish prep | 0.1.0 | CLI subprocess tests; full conformance matrix; MSRV check | release |

Go/no-go reviews after Phases 2 and 4 are explicit user checkpoints; bring complete
verification evidence to the decision point before asking.

## Test architecture

```text
tests/
├── common/mod.rs        # loopback UDP agent harness; FakeClock/FakeRng; fixture loader;
│                        #   golden-bytes compare helper
├── wire.rs              # codec units + hardening: non-minimal unsigned CONTENT rejected;
│                        #   non-minimal length OCTETS accepted (required by
│                        #   test_v3_wire.py:302–327); trailing content, empty INTEGER,
│                        #   OID arc bounds, non-canonical BER vs locate_auth_params
│                        #        (from test_wire_*.py, 1,239 py lines + 3 offset
│                        #   vectors from test_v3_wire.py)
├── rasn_pins.rs         # dependency-behavior pins: 8 executable asserts of rasn
│                        #   0.28.15 decode/encode semantics (risk #11 insurance)
├── property.rs          # proptest (replaces test_wire_fuzz.py):
│                        #   arbitrary bytes → never panic, always Err(Protocol);
│                        #   SnmpValue encode→decode round-trip; OID arc rules
├── crypto_vectors.rs    # LOCKED-ORDER: merged BEFORE src/security/usm/priv.rs exists
├── usm.rs               # engine discovery/recovery, session state, replay windows
├── manager.rs, walk.rs  # loopback vs in-test fake agents incl. walk quirks
│                        #   (backtrack/echo/no-progress — walk.py:79–105 spec)
├── notify.rs, listener.rs, responder.rs, mib.rs, cli.rs
└── conformance/
    └── snmpd.rs         # env-gated live-agent suite (TSNMP_SNMPD=1), the conformance gate
```

- **Unit tests** for internals live `#[cfg(test)]` in their modules. Integration tests
  use the public API only. The reference's internal-helper tests
  (`_encode_signed_integer`, base128, length forms in `test_wire_values.py`) become
  in-module unit tests; the 3 internal-API fuzz targets (`decode_tlv`,
  `decode_length`, `_decode_oid`) fold into the public-surface proptests.
- **rasn behavior is pinned, not trusted**: `tests/rasn_pins.rs` (8 asserts —
  executable evidence from the Phase 1 review) fails loudly if a rasn upgrade
  changes decode/encode semantics. The long-form-length acceptance pin is
  deliberate insurance for risk #11.
- **CLI tests** run the `tsnmp` binary as a subprocess against an in-process responder
  on a fixed port, asserting stdout/exit codes — replaces the reference's 57
  monkeypatch/patch sites (grep-verified); output string-pinning value is preserved.
- **Conformance mechanics**: raw subprocess snmpd (matches the reference's own
  approach), docker-free dev loop, self-skipping when the agent is absent.
  Containerized CI wrapping the same config is a later add; tests are agent-agnostic.

### Fixtures (vendored, then sync)

All fixture directories carry a `SOURCE.md` naming the producing repo + revision.

| Directory | Content |
|---|---|
| `fixtures/crypto-vectors/` | net-snmp 5.9.4 engine-ID + passphrase → localized-key ground truth; draft-reeder Appendix B byte-exact vectors (machine-readable TOML/JSON) |
| `fixtures/bundles/` | tsmi compiled-JSON modules (identical artifacts validate both implementations). The `manifest.json`/`oid_index.json` sidecars are **not** vendored — `mibs-output/` carries none, and both are optional in the format; tests synthesize them (Python: `tests/_bundle_fixtures.py`; Rust: `tests/common/mib.rs`). Provenance: `fixtures/bundles/SOURCE.md` |
| `fixtures/wire-golden/` | byte-exact encodings generated once by the Python codec (v1/v2c/v3 messages) for cross-language byte parity; generated under a **pinned** `cryptography` release (48.0.0 verified full-block CFB — older releases defaulted `modes.CFB` to 8-bit segments, which would corrupt v3-priv goldens) |
| `fixtures/snmpd/` | snmpd.conf matrix: v3 users (tsnmpuser, user224, user384, user512, userSha256Aes192), agents on 127.0.0.1:1161/1162/1171/1173/1174 |

## Risk register

| # | Risk | Mitigation |
|---|---|---|
| 1 | **rasn strictness gap** vs reference hardening (non-minimal unsigned int rejection, trailing content, empty INTEGER) | **RESOLVED (ora-3 review + tests/rasn_pins.rs)**: DER-mode decode + remainder shim + manual `SnmpValue` Decode (~150 LOC). Fallback estimate corrected: a full hand-rolled codec would replicate ~750 reference py-lines (ber.py + asn1.py + pdu.py + message.py), not ~300 — moot, the hybrid stands |
| 2 | **`locate_auth_params` correctness** on non-canonical BER | Port offset test vectors from `test_v3_wire.py`; ~40-line walker with exhaustive unit tests; property-test locator vs rasn decoder agreement |
| 3 | **AES-CFB segment size** — RFC 3826 uses full-block feedback; cfb-mode must match | Crypto-vectors-before-code (locked) + net-snmp interop in Phase 4 |
| 4 | **3DES-EDE decrypt semantics** — no PKCS#7 unpad; truncate to BER extent (usm.py:846–856) | Port `_ber_extent` logic + draft-reeder Appendix B vectors; verify `des`/`cbc` crate API in Phase 0 |
| 5 | **UsmModel lock discipline** (no guard across `.await`) | Module rule enforced by review; single-threaded tokio stress test |
| 6 | **Engine-recovery single-retry semantics** — no loop on repeated REPORTs | `take_recovery()` handshake in the typed flow; scripted fake-agent loopback tests |
| 7 | **Walk termination quirks** (backtrack/echo/no-progress; V1 `noSuchName` as clean end) | Spec-driven tests from the reference's walk-quirk scenarios; range-based responder must satisfy the same |
| 8 | **Community as bytes at the API, String at the CLI** | Accept `String` at CLI boundary (UTF-8 encode), `Vec<u8>` at API boundary; documented |
| 9 | **Fixture drift** between vendored bundles and current tsmi output | Pin producer revision in `SOURCE.md`; CI job regenerates + diffs when tsmi bumps schema; gate semantics (`schema_version ≤ 1.1`) unchanged |
| 10 | **rasn OID arc width** — reference allows arcs to 2³²−1; confirm rasn matches u32 | **RESOLVED**: rasn arcs are u32 with checked-overflow rejection (parser.rs:130–148) — exact match; the `Oid` newtype remains for lexicographic `Ord` and API ownership |
| 11 | **rasn 0.x API churn** — pre-1.0 breaking changes between releases | Pin exact version in Cargo.toml; upgrades are deliberate PRs with wire-golden + conformance as regression net |
| 12 | **Dependency MSRV drift above 1.88** (floor currently set by rasn 0.28's let-chains usage — verified E0658 on 1.85, green on 1.88) | CI job builds on the 1.88 toolchain; a bump that raises the floor is rejected or MSRV is consciously bumped as a decision |
| 13 | **Wire-golden provenance** — fixture bytes depend on the Python crypto version (CFB segment-size history) | Generator pinned to `cryptography` 48.0.0, recorded in `SOURCE.md`; regeneration requires re-verifying against snmpd |
| 14 | **USM engine-recovery vs timeout race** — Python `_request` catches `RequestTimeoutError` AND `EngineRecoveryReportError` before consulting the recovery flag; the Rust manager catches only `Error::EngineRecovery`, so a REPORT racing a timeout may need the timeout-retry path when USM lands (review ora-5, NIT 11) | Revisit the manager retry branch in Phase 3 when `UsmModel` lands; scripted fake-agent loopback tests for the REPORT-then-timeout ordering |
| 15 | **Unbounded engine-id map growth in `V3ReplayGuard`** — the per-engine baseline and per-(engine, username) salt-cache maps grow without bound on a noAuthNoPriv listener that hears many distinct engine IDs (replay.rs; inherited from the reference, notify/v3.py:203–204) | Post-1.0 hardening (bounded engine-id LRU or per-engine TTL); upstream parity for now — the reference has the identical unbounded maps |

Deferred (post-1.0): walk streaming API (`impl Stream`), containerized conformance CI,
criterion benchmarks.
