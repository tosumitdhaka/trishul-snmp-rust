# tsnmp Architecture

Status: finalized design, pre-implementation. This document is the contract the
implementation is built and reviewed against. Python citations refer to the
reference implementation at `/home/dhaka/trishul/trishul-snmp`.

## 1. Locked decisions

| Decision | Choice |
|---|---|
| Approach | Greenfield Rust port; Python `trishul-snmp` is the feature-surface reference, not the API shape |
| Naming | Crate `trishul-snmp`, binary `tsnmp` (both free on crates.io), repo `trishul-snmp-rust` |
| Codec | rasn — verdict delivered (§5.3a): DER-mode decode + remainder shim + manual `SnmpValue` Decode; hand-rolled fallback not needed |
| Async | Async-first on tokio; no sync API (reference has none) |
| Crypto | RustCrypto: hmac, md-5, sha1, sha2, aes+cfb-mode, des+cbc, subtle, zeroize; no FIPS |
| Security-model dispatch | Enum (`Community \| Usm`), no capability probing |
| Unwrap boundary | Typed `UnwrapOutcome` enum, not Option+exceptions |
| Community / username | Community bytewise (`Vec<u8>`), no latin-1 fallback; username `String` — UTF-8 at the wire, matching the reference's `username.encode()` (usm.py:324) |
| License / MSRV | MIT / 1.88 (floor forced by rasn 0.28: let-chains in rasn-derive-impl, which declares no rust-version; verified E0658 on 1.85) |
| Tests | Rust-native redesign; injected Clock/Rng seams; crypto-parity vectors merged before crypto code; live snmpd = conformance gate |

## 2. Goal and non-goals

See [`../README.md`](../README.md) — the README carries the normative goal statement;
this document covers how it is built.

## 3. Crate layout

**Single crate**: package `trishul-snmp` (lib `trishul_snmp`), one bin target `tsnmp`,
edition 2024. A Cargo workspace buys nothing here — one coherent dependency spine
(`wire → security → transport → session → managers`), one version, and a thin CLI
(the reference's `cli/` is ~1.4K lines over a ~9.2K-line library).

The `mib` module is the one plausible future crate (`tsnmp-mib`: pure JSON-in /
enrichment-out, no network dependency). It stays behind a clean `pub mod mib` facade
with `MibBundle: Clone` via `Arc` internals so a later extraction is a directory
move plus a `Cargo.toml` line, not a rewrite. No pre-split.

## 4. Module tree

```text
trishul-snmp-rust/
├── Cargo.toml                    # package trishul-snmp; bin tsnmp; MSRV 1.88
├── fixtures/                     # vendored test data (see docs/plan.md §Test architecture)
│   ├── crypto-vectors/           # net-snmp + draft-reeder ground truth
│   ├── bundles/                  # compiled-JSON MIB modules + sidecars
│   ├── wire-golden/              # byte-exact encode fixtures from Python
│   └── snmpd/                    # snmpd.conf matrix + agent addresses
├── src/
│   ├── lib.rs                    # public re-exports            (← __init__.py)
│   ├── error.rs                  # Error, UnwrapOutcome, EngineReport (← errors.py)
│   ├── types/
│   │   ├── mod.rs
│   │   ├── oid.rs                # Oid newtype                  (← types.py:9, registry.py:77–106)
│   │   ├── value.rs              # SnmpValue enum, Display      (← types.py:41–185)
│   │   └── varbind.rs            # VarBind, OidMatch, Response, ErrorStatus (← types.py:188–238)
│   ├── codec/
│   │   ├── mod.rs                # rasn DER-mode config + remainder shim (← ber.py)
│   │   ├── validate.rs           # typed-side hardening: trap ranges, tag
│   │   │                         #   agreement (← asn1.py, reduced — see §5.3a)
│   │   ├── pdu.rs                # Pdu, PduKind, V1TrapFields   (← pdu.py)
│   │   ├── message.rs           # v1/v2c SnmpMessage            (← message.py)
│   │   └── v3.rs                 # V3Message, UsmSecurityParameters, ScopedPdu,
│   │                             #   locate_auth_params()       (← v3message.py)
│   ├── security/
│   │   ├── mod.rs                # SecurityModel enum           (← model.py)
│   │   ├── community.rs          # CommunityModel               (← community.py)
│   │   └── usm/
│   │       ├── mod.rs            # UsmModel facade: wrap/unwrap/prepare (← usm.py)
│   │       ├── kdf.rs            # Ku/localize, Blumenthal ext, reeder chain
│   │       ├── auth.rs           # truncated HMAC stamp/verify
│   │       ├── priv.rs           # AES-CFB 128/192/256, 3DES-EDE, salt rules
│   │       └── engine.rs         # peer/local engine state, recovery flag
│   ├── transport/
│   │   ├── udp.rs                # UdpClient, UdpServer (bounded queue, drop counters) (← udp.py)
│   │   └── dispatcher.rs         # RequestDispatcher, request-id pool (← dispatcher.py)
│   ├── session.rs                # SnmpSession                  (← session.py)
│   ├── target.rs                 # Target enum + FromStr        (← _runtime.py, dissolved)
│   ├── manager/
│   │   ├── mod.rs                # Manager (v1/v2c/v3 constructors), get/… (← client.py)
│   │   ├── walk.rs               # walk stop rules              (← walk.py)
│   │   └── v1_bulk.rs            # V1 GETBULK→GETNEXT downgrade (← client.py:229–308)
│   ├── notify/
│   │   ├── mod.rs
│   │   ├── sender.rs             # Notifier (v1/v2c/v3 trap/inform) (← notify/client.py)
│   │   ├── listener.rs           # v1/v2c + v3 listeners, drop accounting (← notify/listener.py)
│   │   ├── replay.rs            # V3ReplayGuard, salt LRU, verdicts (← notify/v3.py:145–285)
│   │   ├── v3_path.rs            # probe detect, REPORT encode, inform ack (← notify/v3.py rest)
│   │   └── event.rs             # NotificationEvent + Serialize  (← notify/events.py)
│   ├── responder/
│   │   ├── mod.rs                # V2cResponder                 (← responder/server.py)
│   │   ├── sources.rs            # ResponderSource trait, InMemory, Callback (← sources.py)
│   │   └── rules.rs              # simulation rules             (← rules.py)
│   ├── mib/
│   │   ├── mod.rs                # MibBundle facade (Clone/Arc) (← mib/bundle.py)
│   │   ├── model.rs              # serde types for schema 1.1   (← mib/models.py + registry.py:305–587)
│   │   ├── loader.rs             # load_bundle, sidecars        (← mib/loader.py)
│   │   ├── registry.rs           # symbol/OID indexes            (← mib/registry.py:149–303)
│   │   └── render.rs             # enum/BITS/units enrichment   (← mib/render.py)
│   ├── time.rs                   # Clock + Rng traits, System impls (seams)
│   └── cli/
│       ├── mod.rs                # run() entry                  (← cli/main.py)
│       ├── args.rs                # clap definitions + env secrets (← cli/main.py + common.py)
│       ├── common.rs              # shared plumbing: security/secrets/varbinds (← cli/common.py)
│       └── output.rs             # text/JSON renderers           (← cli/output.py)
├── src/bin/tsnmp.rs              # thin bin: calls trishul_snmp::cli::run()
├── tests/                        # see docs/plan.md §Test architecture
└── benches/                      # placeholder only; no early bench work
```

**Python→Rust merge/split notes**:

- `_runtime.py` (58 lines) dissolves: `normalize_targets` → `target.rs`;
  `response_from_pdu` / `public_varbinds_from_raw_varbinds` → `types/varbind.rs` + manager.
- `wire/ber.py` + most of `asn1.py` shrink into rasn (DER-mode + shims, §5.3a); the
  unsigned-minimality rules become a manual `SnmpValue` Decode; `validate.rs` keeps
  only typed-side checks (OID arc/first-arc rules, trap ranges, tag agreement).
- `security/usm.py` (1,208 lines, largest file in the reference) splits four ways
  (kdf/auth/priv/engine) plus a facade.
- `notify/v3.py` (658 lines) splits into `replay.rs` (self-contained guard state) and
  `v3_path.rs` (listener-side protocol helpers).
- `mib/registry.py`'s ~250 lines of manual `isinstance` normalization collapse into
  serde structs; the `schema_version ≤ 1.1` gate and duplicate-module rejection stay
  as explicit code so policy lives in our tree, not in data.

## 5. Public API design

### 5.1 Core value types

```rust
/// Vec<u32> Ord is lexicographic — matches Python tuple compare (walk.py:36, 88–99 rely on it).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Oid(Vec<u32>);

impl Oid {
    pub fn from_arcs(arcs: &[u32]) -> Result<Self, InvalidOid>;  // ≥2 arcs (asn1.py:186–187) + arc/first-arc rules; NO arc-count cap (reference and rasn have none)
    pub fn parse(s: &str) -> Result<Self, InvalidOid>;
    pub fn arcs(&self) -> &[u32];
    pub fn starts_with(&self, prefix: &Oid) -> bool;
    pub fn display(&self) -> String;
}

/// Enum-of-payload replaces the reference's 13 dataclasses (types.py:41–185).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SnmpValue {
    Integer(i64),          // BER INTEGER is signed; i64 with overflow → Malformed
    OctetString(Vec<u8>),
    Null,
    ObjectIdentifier(Oid),
    IpAddress(Ipv4Addr),   // reference stores a string; display strings stay identical
    Counter32(u32),
    Gauge32(u32),
    TimeTicks(u32),
    Opaque(Vec<u8>),
    Counter64(u64),
    NoSuchObject,
    NoSuchInstance,
    EndOfMibView,
}
```

`IpAddress` is `std::net::Ipv4Addr` internally (4 octets guaranteed on the wire);
`Display` yields the identical `"a.b.c.d"` string, so varbind display output is
byte-identical to the reference.

### 5.2 VarBind / Response

One `VarBind` type — the reference's `RawVarBind` vs enriched `VarBind` split buys
nothing in Rust and costs a conversion layer:

```rust
#[derive(Clone, Debug)]
pub struct VarBind {
    pub oid: Oid,
    pub value: SnmpValue,
    // enrichment — None until a bundle renders it (render.py:19–60)
    pub matched: Option<OidMatch>,     // Python field `match` (keyword); renamed
    pub display_name: Option<String>,
    pub display_value: Option<String>,
    pub enum_label: Option<String>,
    pub units: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Response {
    pub request_id: u32,
    pub error_status: ErrorStatus,
    pub error_index: u32,
    pub varbinds: Vec<VarBind>,
}
```

### 5.3 PDU and messages

```rust
pub enum PduKind {
    GetRequest, GetNextRequest, Response, SetRequest, Trap /* v1, 0xA4 */,
    GetBulkRequest, InformRequest, SnmpV2Trap, Report,
}
```

`Report` is added. The reference excluded 0xA8 from its PDU tag enum and paid with
three duplicated hand-parsers (`usm.py:1085–1174`, `notify/v3.py:555–612`); including
it removes ~90 lines of duplication. REPORT-specific validation becomes one code path.
Golden bytes are unaffected.

```rust
pub struct V1TrapFields {           // pdu.py:57–62
    pub enterprise: Oid, pub agent_addr: Ipv4Addr,
    pub generic_trap: u8,           // validated 0..=6
    pub specific_trap: i32, pub timestamp: u32,
}

pub struct Pdu {
    pub kind: PduKind,
    pub request_id: u32,
    pub error_status: i32,          // raw: doubles as non-repeaters in GETBULK
    pub error_index: i32,           // raw: doubles as max-repetitions in GETBULK
    pub varbinds: Vec<VarBind>,
    pub v1_trap: Option<V1TrapFields>,  // Some iff kind == Trap
}
impl Pdu {
    // getters saturate negative raw values to 0 (no reference coverage; the
    // reference's walk uses min(non_repeaters, len(oids)) — client.py:251)
    pub fn non_repeaters(&self) -> u32; pub fn max_repetitions(&self) -> u32;
}

pub struct SnmpMessage {
    pub version: SnmpVersion,       // V1 | V2c (wire ints 0 | 1)
    pub community: Vec<u8>,        // bytewise, no latin-1 fallback
    pub pdu: Pdu,
}

pub struct UsmSecurityParameters {  // v3message.py:25–34
    pub engine_id: Vec<u8>, pub engine_boots: i32, pub engine_time: i32,
    pub username: Vec<u8>, pub auth_params: Vec<u8>, pub priv_params: Vec<u8>,
}
```

**Auth-offset design.** USM verification must zero-fill `authParams` at its byte
position in the received datagram and recompute the HMAC; the reference derives
that offset from parser state to survive non-canonical BER length forms
(`v3message.py:113–120`, `usm.py:622–645`). rasn's `Decode` does not report field
offsets, so `codec::v3::locate_auth_params(&[u8]) -> Result<usize, ProtocolError>`
hand-walks the fixed outer structure (SEQ → INTEGER → header SEQ → securityParameters
OCTET STRING → inner SEQ → 5th field) and returns the content offset. On the send
side we control encoding: emit a zero placeholder, locate, splice the HMAC.

**Zero-fill semantics (byte-exact, usm.py:640–644).** Verification zeroes
**exactly `tag_len` bytes at the located offset** — not the received field's
length — and compares only the first `tag_len` bytes of the received value.
Consequences to replicate: an over-long received auth field contributes its extra
bytes raw to the MAC input but they are ignored for comparison; an under-long
field lets zeros spill into the following TLV (framing altered, MAC fails). Send
side (`usm.py:622–629`): the placeholder is exactly `tag_len` zero bytes before
splicing the computed HMAC.

### 5.3a rasn configuration and strictness shims (codec contract)

Verified against rasn 0.28.15 by executable evidence (`tests/rasn_pins.rs`, 8/8
pins) plus the independent ora-3 source review:

1. **Decode runs under `DecoderOptions::der()`.** rasn's BER mode accepts
   indefinite lengths and constructed OCTET STRINGs — both rejected by the
   reference (`ber.py:28–29`; tag 0x24 ≠ 0x04). DER mode rejects both
   (`ConstructedEncodingNotAllowed`) and accepts everything the reference accepts
   for the SNMP type set, long-form length octets included (required by
   `test_v3_wire.py:302–327`).
2. **Top-level trailing-content shim.** `ber::decode` ignores trailing bytes; the
   reference rejects them (`ber.py:53–56` `expect_end`). Use
   `decode_with_remainder` + assert-empty at the message/payload boundaries.
3. **Manual `Decode` for `SnmpValue`** (+ the `IpAddress` 4-octet rule): rasn
   accepts non-minimal unsigned content (`02 02 00 01` → 1, both modes) and its
   over-width stripping silently corrupts values (`00 01 00 00 00` → 16777216;
   i64 sign-inversion on `00 FF…×8` → −1). A manual impl decoding via
   `rasn::types::Any` (`as_bytes()` preserves the raw content slice) applies the
   exact `asn1.py:132–182` rules: unsigned minimality (re-encode compare),
   u32/u64 width bounds, 4-octet IpAddress. ~100–200 LOC. **`Encode` is manual
   too** (implementation finding, Phase 1): rasn's derived `Vec<u8>` encoder
   emits SEQUENCE OF, not OCTET STRING (`enc.rs:1033–1045`, no special case);
   the manual encoder is byte-exact — minimal lengths, leading-`00` for MSB —
   proven by the 26 golden cases.
4. **`validate.rs` scope** shrinks to what post-decode state can actually see:
   OID arc/first-arc rules on the typed side, V1 trap-field ranges,
   tag-vs-privParams agreement. Unsigned minimality moved into the manual
   `Decode` (item 3).
5. **Varbind lists decode strictly, manually.** rasn's `decode_sequence_of`
   silently DROPS a malformed element whose error occurs after its TLV is fully
   consumed — e.g. a well-framed empty INTEGER: the element loop breaks on the
   first error and returns the decoded prefix (`ber/de.rs:732–765`, both
   modes), and the extent check finds nothing left to reject. Tag mismatches,
   by contrast, leave the tag byte unconsumed and surface as
   `UnexpectedExtraData`. A malformed trailing varbind would therefore vanish
   instead of failing the message; `RawVarbindList` walks the content with the
   strict TLV decoder and errors on any framing/tag/content mismatch. Pinned
   in `tests/rasn_pins.rs` (pin #9).

### 5.4 Security model — enum dispatch

```rust
#[derive(Clone)]
pub enum SecurityModel {          // replaces the structural Protocol + every hasattr probe
    Community(CommunityModel),
    Usm(UsmModel),
}

impl SecurityModel {
    pub fn wrap_pdu(&self, pdu: &Pdu) -> Result<Vec<u8>, Error>;
    pub fn unwrap_message(&self, data: &[u8]) -> UnwrapOutcome;
    pub async fn prepare(&self, dispatcher: &RequestDispatcher) -> Result<(), Error>;
    //   ^ only Usm performs RFC 3414 discovery; Community returns Ok. Static capability
    //     via match arms — the Python hasattr disappears. &self, not &mut: the Mutex
    //     provides interior mutability, and prepare must be callable from &self
    //     methods (lazy discovery inside send_inform, notify/client.py:300–303).
    pub fn take_recovery(&self) -> Option<EngineReport>;
}

pub enum AuthProtocol { None_, Md5, Sha1, Sha224, Sha256, Sha384, Sha512 }
pub enum PrivProtocol { None_, Aes128, Aes192, Aes256, Des3Ede }   // no DES-CBC (locked)

pub struct UsmUser {              // construction-validated: new() -> Result<Self, Error>
    pub username: String,
    pub auth_protocol: AuthProtocol,
    pub auth_key: AuthKey,        // Passphrase(Vec<u8>) | Localized(Zeroizing<[u8; 64]>)
    pub priv_protocol: PrivProtocol,
    pub priv_key: PrivKey,
}

pub struct UsmLocalEngine { pub engine_id: Vec<u8>, pub engine_boots: u32, pub engine_time: u32 }
```

**Dispatcher↔security ownership.** The receive loop needs `unwrap_message`, so
`RequestDispatcher` holds an `Arc<SecurityModel>` clone — mirroring the reference,
where the dispatcher holds the shared security object (`dispatcher.py:41`).
`SnmpSession` stores `security: Arc<SecurityModel>` and hands a clone to its
dispatcher. No circular dependency: the dispatcher is a sibling, exactly as in
Python.

**`UsmModel` interior mutability: `std::sync::Mutex` around engine state, `&self`
everywhere.** Rationale:

- Manager path: all USM mutations happen under the session's request lock in the
  reference (`manager/client.py:142`) — exclusive access exists in practice, but
  threading `&mut` forces `&mut Session` on every operation and breaks `Arc<Manager>`
  for concurrent polling.
- Listener path: the codec is shared across `receive()` iterations with no exclusive
  access (`listener.py:283`, `notify/v3.py:315`) — `&mut self` cannot work there.
- Locked sections are CPU-bound (hash, HMAC, AES) and never span an `.await`.
- **Module rule**: no method holds the lock guard across an await point.

```rust
pub struct UsmModel {
    user: UsmUser,
    context_name: Vec<u8>,
    local_engine: Option<UsmLocalEngine>,
    state: Mutex<UsmEngineState>,  // peer boots/time + monotonic anchors, key LRU
}                                  // caches (cap 64), last CBC salt octet, recovery flag
```

### 5.5 Session and manager

```rust
pub struct SnmpSession {
    bundle: Option<Arc<MibBundle>>,
    security: Arc<SecurityModel>,          // cloned into the dispatcher's receive loop
    client: UdpClient,                     // tokio UdpSocket, connected
    dispatcher: RequestDispatcher,
    request_lock: tokio::sync::Mutex<()>,  // Python asyncio.Lock (client.py:142)
}

pub struct Manager { session: SnmpSession, version: SnmpVersion }
impl Manager {
    pub async fn connect_v1(cfg: V1Config) -> Result<Self, Error>;
    pub async fn connect_v2c(cfg: V2cConfig) -> Result<Self, Error>;
    pub async fn connect_v3(cfg: V3Config) -> Result<Self, Error>;
    // One struct + constructors instead of V1/V2c/V3Manager classes; behavior keyed
    // off `version` (the reference keys off CommunityModel.version, client.py:198–344).

    pub async fn get(&self, targets: impl IntoIterator<Item = impl Into<Target>>) -> Result<Response, Error>;
    pub async fn get_next(&self, /* same */) -> Result<Response, Error>;
    pub async fn get_bulk(&self, targets: /* same */, non_repeaters: u32, max_repetitions: u32) -> Result<Response, Error>;
    pub async fn walk(&self, root: impl Into<Target>, opts: WalkOptions) -> Result<Vec<VarBind>, Error>;
    pub async fn bulkwalk(&self, root: impl Into<Target>, opts: WalkOptions) -> Result<Vec<VarBind>, Error>;
}
```

**Constructor shape (leaner than the sketch)**: the v1/v2c configs are aliases of one
`CommunityConfig` (`pub type V1Config = CommunityConfig;` etc. — the §5.5 names stay
public), and `connect_v1`/`connect_v2c` delegate to a shared private
`connect_community(cfg, version)` in each of Manager and Notifier; `V3Config` is a
genuinely distinct struct (Phase 3). The single shared `Default` carries the manager's
port 161; trap senders set the notifier port explicitly. Behavior identical to the
"6 constructors + 6 config structs" reading of the sketch.

**Lifecycle**: async `connect()` constructors (socket + USM discovery — the reference's
`session.open()` including the `prepare` hook, `session.py:53–63`); teardown is `Drop`.
No async context manager and no explicit `close()` — dropping the tokio `UdpSocket`
closes it, which collapses the reference's drain-on-close sentinel machinery
(`udp.py:140–156`) into channel close.

**Single-flight semantics preserved**: concurrent calls on one manager queue via
`request_lock`; they never parallelize. Documented API behavior, same as the reference.

**Lock discipline**: tokio's `Mutex` is non-reentrant — no method holds `request_lock`
while calling another method that acquires it. `walk`/`bulkwalk` and the V1 GETBULK
downgrade lock per-request (matching the reference, which locks inside `_request`,
`client.py:142`), so concurrent walks interleave at request granularity — identical
semantics to Python.

`Target` (dissolved `_runtime.py` + `registry.py:109–125`):

```rust
pub enum Target { Numeric(Oid), Symbolic { module: String, symbol: String, suffix: Vec<u32> } }
impl FromStr for Target { /* "1.3.6.1…" | "IF-MIB::ifDescr.1" */ }
```

### 5.6 Notify

```rust
pub struct Notifier { session: SnmpSession, version: SnmpVersion }
impl Notifier {
    pub async fn connect_v1/v2c/v3(/* … */) -> Result<Self, Error>;
    //   v3 trap-only construction skips eager discovery (client.py:276–283)
    pub async fn send_trap(&self, notification: impl Into<Target>, varbinds: /* … */, uptime: u32) -> Result<u32, Error>;
    //   ^ returns the assigned request id (parity, notify/client.py:104)
    pub async fn send_v1_trap(&self, spec: V1TrapSpec /* enterprise/generic/specific/agent_addr */) -> Result<u32, Error>;
    pub async fn send_inform(&self, notification: impl Into<Target>, /* … */) -> Result<Response, Error>;
}
// Auto sysUpTime/snmpTrapOID varbind ordering preserved (client.py:349–377).

pub struct NotificationListener { /* v1/v2c */ /* … */ }
pub struct V3NotificationListener { /* user, local_engine, codec: Arc<UsmModel>, replay_guard */ /* … */ }
impl /* both */ {
    pub async fn bind(cfg: ListenerConfig) -> Result<Self, Error>;
    pub async fn recv(&mut self) -> Option<Result<NotificationEvent, Error>>;  // None = closed
    pub fn drop_counts(&self) -> &DropCounts;       // 9-reason taxonomy, notify/v3.py:90–107
    pub fn local_addr(&self) -> SocketAddr;
}
```

The reference's `__aiter__/__anext__` becomes `recv() -> Option<…>`. Shape: `bind()`
spawns a background receive task; `recv()` pulls decoded events from an mpsc channel.
**Teardown is explicit**: the listener holds a cancellation token; `Drop` signals it,
the task (select!ing on the token in its recv loop) wakes and exits, the channel
sender drops, and pending `recv()` calls return `None`. Drop alone cannot wake a task
blocked on `socket.recv()` while co-owning the socket — the token is the deterministic
shutdown the reference's drain-on-close sentinels approximate. Stream adapters are a
post-1.0 enhancement.

`NotificationEvent` implements `Serialize` with `skip_serializing_if` for `Option`
fields and hex-encoded byte fields — replaces the hand-built `to_dict()`.

### 5.7 Responder

```rust
pub trait ResponderSource: Send + Sync {               // sources.py:34–41
    fn lookup_exact(&self, oid: &Oid) -> Option<SnmpValue>;
    fn lookup_next(&self, oid: &Oid) -> Option<(Oid, SnmpValue)>;
}

pub struct InMemoryObjectSource { objects: BTreeMap<Oid, ObjectValue>, /* bundle */ }
pub enum ObjectValue { Static(SnmpValue), Rule(Box<dyn SimulationRule>) }
pub trait SimulationRule: Send + Sync { fn get_value(&self) -> SnmpValue; }
```

`BTreeMap<Oid, _>` replaces the reference's dict + sorted list + `bisect`/`insort`
(`sources.py:54–96`); `range()` gives lexicographic `lookup_next` directly. Rules
take `&self` (shared source across awaits): counters use interior atomics, uptime
uses an injected Clock. GETBULK truncation halving loop (`server.py:187–205`) ports
as-is.

**Panic observability.** The serve loop isolates per-datagram handler panics
(`catch_unwind`), logs them to stderr (`responder: …`), counts them on
`SnmpResponder::panic_count`, and drains the raw payload texts of the most recent
ones through `SnmpResponder::recent_panics` (bounded at 32, oldest dropped) —
the typed equivalent of the reference's exception-raising `receive()` when no
event channel exists (`serve` is the only consumer).

### 5.8 MibBundle

```rust
#[derive(Clone)]
pub struct MibBundle { inner: Arc<RegistryInner>, source: PathBuf }
impl MibBundle {
    pub fn resolve(&self, target: &Target) -> Result<Oid, Error>;
    pub fn display_symbolic(&self, oid: &Oid) -> Option<String>;  // "IF-MIB::ifDescr" form
                                                                   //   (registry.py:219–236; CLI translate)
    pub fn lookup(&self, oid: &Oid) -> Result<OidMatch, UnknownOid>;   // longest-prefix
    pub fn lookup_metadata(&self, oid: &Oid) -> Option<NodeMetadata>;
    pub fn iter_objects(&self, filter: ObjectFilter) -> impl Iterator<Item = &MibNode>;
    pub fn search(&self, query: &str, opts: SearchOptions) -> Vec<&MibNode>;
    pub fn enrich(&self, varbinds: Vec<VarBind>) -> Vec<VarBind>;
}
pub fn load_bundle(path: impl AsRef<Path>) -> Result<MibBundle, Error>;
```

serde types carry the schema-1.1 contract; the `schema_version ≤ 1.1` gate and
duplicate-module rejection stay explicit code. `BundleValidationError` keeps a `path`
field (mirrors `errors.py:16–23`) so error semantics for bundle authors survive.

## 6. Error taxonomy

One top-level enum plus two supporting enums. Derive machinery (thiserror vs manual)
is an implementation choice; the shape below is the contract.

```rust
pub enum Error {
    Protocol(ProtocolError),          // malformed/unsupported wire data; carries byte offset
    Transport(TransportError),        // bind/connect/send failures
    Timeout { attempts: u8 },         // retries exhausted
    Authentication,                   // HMAC mismatch; Debug must never contain key material
    EngineRecovery(EngineReport),
    WalkAborted { status: ErrorStatus, index: u32 },
    Bundle(BundleError),              // incl. BundleValidationError { path }
    Translation(TranslationError),    // InvalidOid / UnknownSymbol / UnknownOid
    InvalidInput(String),             // constructor validation
}

pub struct EngineReport {            // reference carries raw report bytes (errors.py:62–64)
    pub raw: Vec<u8>,
    pub engine_id: Vec<u8>, pub engine_boots: u32, pub engine_time: u32,
}
```

**Unwrap outcome** — replaces `unwrap_message -> Pdu | None` + exception selection
(`usm.py:341–391`, `community.py:41–47`, consumed at `dispatcher.py:178–195`):

```rust
pub enum UnwrapOutcome {
    Ok(Pdu),
    NotForUs,                    // wrong community/user/engine: silent skip
    Malformed(ProtocolError),    // listeners count + drop; dispatcher skips
    AuthFailed,                  // HMAC failure: surfaces, never swallowed as NotForUs
    EngineRecoveryPending,       // usmStatsNotInTimeWindows REPORT; model already adopted state
}
```

**Engine-recovery flow (typed, not flag+exception).** The reference signals via a
mutable flag probed with `getattr`, an exception carrying bytes, and a
`consume_engine_recovery()` handshake, retried in `manager/client.py:150–169` and
`notify/client.py:307–322`. In Rust: `unwrap_message` returns
`EngineRecoveryPending`; the dispatcher maps it to `Err(Error::EngineRecovery(..))`
only if `security.take_recovery()` confirms adoption (preserving the reference's guard
against stray/duplicate REPORTs — a second REPORT after retry must not loop,
`client.py:165–169`); the manager catches, consumes the report, retries exactly
once, then propagates. One retry, no flag polling, identical semantics.

## 7. Seams: Clock and RNG

Two tiny traits in `time.rs`, `Arc<dyn _>`-injected via the configs of Clock
*consumers* (see the table below) — not defaulted into configs that have no
consumer. These replace the monkeypatch surfaces of the Python test suite.

```rust
pub trait Clock: Send + Sync {
    fn monotonic(&self) -> Duration;   // engine-time anchors, replay windows, drop-log rate limits
    fn unix(&self) -> u64;             // TimestampRule
}
pub struct SystemClock;

pub trait Rng: Send + Sync { fn fill_bytes(&self, buf: &mut [u8]); }
pub struct SystemRng;                  // OS CSPRNG
```

| Consumer | Seam use | Reference |
|---|---|---|
| `UsmModel` | monotonic (engine-time anchors) | usm.py:286–290, 475–497 |
| `V3ReplayGuard` | monotonic (±150 s windows) | notify/v3.py:199–264 |
| `UdpServer` + listeners | monotonic (rate-limited drop logs) | udp.py:176–204 |
| `RequestDispatcher` | Rng (31-bit request ids, collision-checked) | dispatcher.py:46–52 |
| `UsmModel` priv path | Rng (AES salt; CBC salt first-octet tweak) | usm.py:741, 955–969 |
| Simulation rules | monotonic + unix + Rng | rules.py:77–129 |
| Dispatcher timeouts | **tokio::time**, not the trait | dispatcher.py:171–177 |

The last row is deliberate: tokio's test-time auto-advance is the better tool for
deadlines; the `Clock` trait exists only where monotonic values fold into protocol
state, which tokio cannot provide.

## 8. Deliberate deviations from the Python reference

| Deviation | Reference behavior | Reason |
|---|---|---|
| `SnmpValue` enum | 13 dataclasses | Rust shape; display strings preserved |
| Single `VarBind` | RawVarBind vs enriched VarBind | No conversion-layer cost |
| `PduKind::Report` added | 0xA8 excluded; 3 hand-parsers | Removes ~90 duplicated lines |
| `IpAddress` = `Ipv4Addr` | string | Display identical |
| Community/username as bytes | UTF-8 w/ latin-1 fallback | Locked decision |
| Enum `SecurityModel` | Protocol + hasattr/getattr probing | Locked decision |
| `connect()` + `Drop` lifecycle | async context manager + manual close | Rust idiom; closes drain machinery |
| `recv()` listener API | `__aiter__`/`__anext__` | tokio-mpsc idiom |
| `UsmUser::new -> Result` | panicking `__post_init__` | Rust convention |
| Datagram size fixed 65535 (`MAX_DATAGRAM_SIZE`) | configurable `max_datagram_size` constructor param | No test or real deployment need; revisit if fragmented transport matters |
| Typed `UnwrapOutcome` + `EngineRecovery` variant | exception/flag/getattr flow | Locked decision |
| `BTreeMap` responder source | dict + sorted list + bisect/insort | `range()` gives lexicographic next directly |
| One `Manager` + version | V1/V2c/V3Manager classes | No inheritance in Rust |
| `Integer(i64)` bound | unbounded Python int | Manual `Decode` rejects over-width/non-minimal unsigned content exactly as `asn1.py:178–179`; signed INTEGER content longer than 8 octets → Malformed (even when magnitude fits i64) |
| PDU header INTEGERs decode via rasn i64 path | reference's hand decoder rejects over-width | `request_id`/`error_status`/trap fields accept 9-octet content (decodes to u32::MAX image) where values reject it; no reference test covers — accepted divergence (the promised Phase 3 convergence was not implemented; no reference coverage either way) |
| Negative engineBoots/engineTime on the wire clamp to 0 on adoption | Python adopts the raw negative value | Rejected as nonsensical state (boots/time are counters); no reference coverage |
| OctetString display uses `!is_control()` | `isprintable()` | Format/line-separator code points render as text instead of hex; documented in code |
| Early OID arc rejection in `Oid::from_arcs` | parse accepts large arcs, fails only at encode | Strictly earlier failure point; harmless |
| Listener `on_error` callback dropped | per-drop callback (listener.py:60) | `drop_counts()` polling replaces it |
| `Pdu.request_id: u32` | signed int preserved on decode | Negative INTEGER content reinterpreted as its unsigned image; no reference test covers it, practice never sends negative ids |
| Version checked during structural decode | version checked after full decode (`message.py:62`) | Derive-level ordering; no test depends on it — accepted divergence |
| Transport errors during the listener receive loop close the listener (`recv()` → `None`) | re-raised out of `__anext__` when not closed (`listener.py:88–94`) | Drop-based teardown has no distinct "not closed" state to re-raise against; the reference's anext-transport tests have no Rust equivalent |
| Listener panic policy: a panic inside the per-datagram handler is caught (`catch_unwind`, `AssertUnwindSafe`) and surfaced as an `Err` event | exception raises out of `receive()` | The typed equivalent; without it a panic would kill the receive task and read as teardown (`recv() → None`) |
| `V3ReplayGuard` engine tracking bounded to `engine_cap` (default 1024, LRU) | unbounded per-engine baseline and salt-cache dicts (notify/v3.py:203–204) | Only noAuthNoPriv traffic reaches the guard (auth verification precedes it), so a listener hearing many distinct engine IDs could grow the reference's maps without bound; the Rust guard evicts the least-recently-used engine at the cap — its next datagram reverts to first-seen adoption, identical to a brand-new engine (`src/notify/replay.rs` `adopt_engine`). Recency tracking is amortized O(1): touched engines push a fresh recency entry and leave the superseded one as a lazy tombstone, swept once the dead entries reach the live bound |
| `UdpServer` queue-overflow drops counted separately (`UdpServer::dropped`) | same single `dropped` counter surface | The listener's 9-reason `DropCounts` taxonomy covers only datagrams the listener actually read; the socket-queue overflow counter predates the listener and stays independent (documented on `DropCounts`) |
| `MibBundle::display_symbolic` returns `Result<String, Error>` | raises `UnknownOidError` | The §5.8 sketch's `Option<String>` cannot carry the reason; the raising form is kept and callers use `.ok()` where an option suffices |
| `MibBundle::lookup` returns `Result<OidMatch, Error>` carrying `TranslationError::UnknownOid` | raises `UnknownOidError` | No standalone `UnknownOid` type in the §6 taxonomy; the error rides the top-level `Error` like the sibling facade methods |
| `iter_objects`/`iter_notifications`/`search` take positional filters | keyword-only `module=`/`type_filter=`/`limit=` | Rust convention; `search`'s default `limit=100` is always explicit at the call site |
| `response_from_pdu` always sets `display_value` | `enrich_varbinds(None)` sets the raw display string | Verified additive: `enrich_varbinds(None, …)` parity (render.py:22–30) — without a bundle every other enrichment field is reset to `None`, exactly like the reference's fresh-VarBind construction |
| `SnmpSession::from_parts` takes a `bundle` parameter | constructor param on the session | Test seam; keeps the bundle field reachable without a network connect |
| `TranslationError::Message` variant | base `TranslationError` carries free-form messages | The taxonomy's three typed variants cannot express base-class messages like "Translation target cannot be empty" |
| Iteration order is BTreeMap-sorted (modules, objects) | Python dict insertion order | Deterministic `Ord`; observable in `iter_objects`/`iter_notifications`/`search` output order and in which label wins when two labels share one enum number — no reference test depends on it |
| Bundle-node `oid`/`oid_path` parsing maps malformed OIDs to `BundleError::Validation` | `parse_oid` raises `InvalidOidError` | Both reject; in Python `InvalidOidError` is itself a `BundleError` subclass, so the Rust `Bundle` branch is the matching taxonomy ancestor |
| Collection fields (`imports`/`objects`/`notifications`/`types`) reject explicit JSON `null` | `payload.get(key, {})` returns the stored `None` and the isinstance check rejects it | Present-`null` read from the raw payload object (serde's `Option` cannot distinguish absent from null); `module_metadata: null` stays accepted by both |
| OID-index sidecar keys are always JSON strings | `_load_oid_index` rejects non-string dict keys | JSON object keys are strings by construction; the reference's non-string-key case (reachable only via monkeypatch) is re-specified as malformed-string-key rejection in the tests |
| serde 128-deep JSON recursion limit | unbounded Python `json` nesting | ~130-deep module JSON fails with `BundleValidationError`; real tsmi bundles nest ~5 deep |
| Bundle-path `~`/`~/`/`~user` expansion (unix) | `Path.expanduser()` also handles `~user` | `~user` expands on unix via a std-only `/etc/passwd` parse (no `pwd` dependency, no unsafe) — the parsed content is pure-function-tested with fixtures; an unknown user falls through to the literal path and "Bundle path does not exist" exactly as before; non-unix keeps the `~`/`~/`-only limitation (`src/mib/loader.rs` `expanduser`/`passwd_home_for`) |
| v1 requests ANSWERED (RFC 1157 semantics) | v1 dropped at the receive boundary (server.py:136–140; `test_v2c_responder_drops_v1_requests`) | The Phase 7 spec requires v1 GET/GETNEXT answering; v1 has no v2 exception values, so a missing GET / GETNEXT past the end answers `noSuchName` (error-status 2, error-index = first failing varbind, request varbinds echoed) — the v1 manager's walk terminates on that cleanly (`walk.rs:61`). A hand-crafted v1 message carrying the v2c-only GETBULK PDU tag is dropped without a response (RFC 1157 has no GETBULK; answering would produce a protocol-invalid v1 response — `src/responder/mod.rs` `build_response_pdu`). The reference's drop test is INVERTED (`tests/responder.rs:responder_answers_v1_requests`) |
| v1 SET → `readOnly` (4) | v2c SET → `notWritable` (17); no v1 answer path at all | RFC 1157's error-status set has no notWritable; `readOnly` is the v1 read-only rejection (`src/responder/mod.rs` `build_response_pdu`) |
| v3 USM answer path added | no v3 responder in the reference | The Phase 7 spec's v3 path: discovery REPORT (reuses `notify::v3_path::encode_discovery_report`), auth verify + priv decrypt (shared `decode_v3_auth_priv`), response stamped under the configured local engine (shared `encode_v3_response`); one configured user, wrong-user datagrams dropped |
| Responder non-in-memory mutators → `Error::InvalidInput` | `TypeError` (server.py:169–172) | No `TypeError` in the §6 taxonomy; `InvalidInput` is the typed equivalent |
| `serve(count)` negative-count rejection unrepresentable | `ValueError` on negative `count` (server.py:111) | `usize` count; `serve(0)` = run until closed, `close()`/`Drop` cancel the loop |
| Rule value types are closed enums (`CounterValueType`/`RandomValueType`/`TimestampValueType`) | `_IntConstructible` callable accepted per rule (rules.py:19–34) | The tested surface (Counter32/64, Gauge32/Integer, Integer/Counter32) is a closed set; the wire modulus follows the enum |
| `RandomNumericRule` with `max < min` pins the span to one value (always returns `min`) | `random.randint(min, max)` raises `ValueError` on an inverted range | `u64` span arithmetic saturates instead of erroring; outside the reference's tested surface, documented on the constructor (`rules.rs:RandomNumericRule::new`) |
| `UptimeRule`/`TimestampRule` read the injected `Clock`; `RandomNumericRule` the injected `Rng` | Python global `time`/`random`, `_start` monkeypatch (rules.py:103–130) | §7 seam policy; the reference's `rule._start` monkeypatch is re-specified on the `FakeClock` |
| GETBULK unencodable-response drop is unrepresentable for v2c | `Counter32Value(2**32)` constructs but cannot encode; the response is dropped and the loop survives (test_responder.py:684–712) | `SnmpValue::Counter32(u32)` cannot hold 2**32; the loop-resilience property is re-specified on the v3 path (`tests/responder.rs:responder_recovers_from_bad_datagram` — a bad-HMAC datagram drops, the next request is answered) |
| CLI DES-CBC rejection message names the Rust lockout, not the Python backend | "the installed cryptography package no longer exposes a single-DES primitive" | The Rust toolkit locks DES-CBC out by design (§1); the message shape ("DES-CBC privacy is unavailable: … use aes128, aes192, aes256, or 3des-ede") and exit code 1 are preserved (`src/cli/common.rs` `parse_priv_protocol`) |
| CLI counter32/gauge32/timeticks values ≥ 2³² and integers beyond i64 fail at parse | the reference's dataclasses accept them and fail only at encode | `SnmpValue` is a typed enum (§5.1) that cannot represent those values; the failure is strictly earlier with a clear message (`src/cli/common.rs` `parse_non_negative_u32`) |
| CLI varbind `ip` values parse to `Ipv4Addr` at parse time | `IpAddressValue` stores a raw string, validated at encode | Same category of failure, earlier; "Invalid IP address" message (`src/cli/common.rs` `parse_snmp_value`) |
| CLI rewraps `Error::WalkAborted` into the reference's `WalkError` text | `WalkError` is the library's message | The library's `Error::WalkAborted` Display is "walk aborted: {status:?} at index {index}" (§6); the CLI boundary restores the reference's "walk aborted: agent reported {label} (error-index {index})" so pinned strings match (`src/cli/mod.rs` `cli_error`) |
| `--count -1` needs clap `allow_hyphen_values` | argparse accepts negative numbers natively | clap rejects a leading `-` value as a flag unless opted in; the validation message and exit code are unchanged (`src/cli/args.rs` `ListenArgs::count`) |
| `tsnmp` is the only installed binary | both `tsnmp` and `trishul-snmp` console scripts (pyproject) | Cargo declares the single `tsnmp` bin; the reference's pyproject console-script pin is not portable |
| CLI tests run the binary as a subprocess against in-process responder/listener on deterministic fixed-base ports | pytest `main([...])` with monkeypatched managers/notifiers | The plan's subprocess-test design replaces the reference's 57 monkeypatch/patch sites while preserving the pinned output strings (`tests/cli.rs`) |
| CLI `version` subcommand prints the crate version | prints the package `__version__` | Identical surface; the value source differs (`src/cli/mod.rs` `handle_version`) |
| CLI trap `--agent-addr` parses to `Ipv4Addr` at parse time | `IpAddressValue` stores a raw string, validated at encode | Same category as the varbind `ip` row above; "Invalid agent address: …" message (`src/cli/mod.rs`) |
| Output renderer keeps an empty `Some("")` display value as the empty string | Python's `or` treats `""` as falsy and falls back to the raw display | Unreachable in practice (no reference path produces an empty display string); documented for exactness (`src/cli/output.rs`) |
