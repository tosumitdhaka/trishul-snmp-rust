# snmpd — provenance

## Source

- Repository: `/home/dhaka/trishul/trishul-snmp` (Python reference, "trishul-snmp")
- Git revision: `1b01976356d61f508a6bbab32f232aa65a0909cd`
- Source files:
  - `.github/workflows/quality.yml` lines 127–135 — the main agent
    (`127.0.0.1:1161` v1/v2c community `public`, `127.0.0.1:1162`
    SNMPv3) launched by the CI snmpd job;
  - `tests/test_snmpd_integration.py` — the restricted-VACM agent
    (`_SNMPD_VIEW_CONFIG`, lines 651–663), the v3-only agent
    (`_SNMPD_V3ONLY_CONFIG`, lines 670–677) and the coldStart
    notification fixture (lines 395–402).

## Users (7 total, all passphrases byte-identical to the source)

| User | Auth | Priv | Source |
|------|------|------|--------|
| tsnmpuser | SHA-256 | AES-256 | quality.yml (main agent, :1162) |
| user224 | SHA-224 | AES-256 | quality.yml |
| user384 | SHA-384 | AES-192 | quality.yml |
| user512 | SHA-512 | AES-256 | quality.yml |
| userSha256Aes192 | SHA-256 | AES-192 | quality.yml |
| v3view | SHA-256 | AES-128 | test_snmpd_integration.py (:1173) |
| v3only | SHA-256 | AES-128 | test_snmpd_integration.py (:1174) |

All auth passphrases are `authpassword12345` and all priv passphrases
are `privpassword12345`, exactly as in the sources.

## Agent addresses (5 listeners, one process)

`127.0.0.1:1161` (v1/v2c), `:1162` (v3 crypto matrix), `:1171`
(notifications), `:1173` (restricted view), `:1174` (v3-only user).

## Adaptations (single-process merge)

1. **One engineID per process.** The CI main agent pins
   `engineID reederinvest`; the dedicated test agents used
   `engineID restrictedVACM` / `engineID v3onlyengine`. This config
   keeps `reederinvest` and re-pins the `v3view`/`v3only` `createUser
   -e` values to `0x80001f8804726565646572696e76657374`. Passphrase-based
   clients localize against the discovered engine, so behavior is
   unchanged; only pre-localized key stores would notice.
2. **Restricted-view community renamed** from `public` to `restricted`
   (`com2sec restsec 127.0.0.1 restricted`). In one process, community
   `public` already maps to the main agent's unrestricted `rocommunity`;
   the first matching com2sec wins, so keeping `public` would silently
   grant full access and defeat the view. View/group/access lines are
   otherwise byte-identical.
3. **v3-only drop property not reproducible.** The reference's `:1174`
   agent had no community config at all (community requests silently
   dropped); in this shared process `:1174` also answers community
   `public`. The `v3only` user itself is preserved. To test the silent
   drop, launch the original two-line `_SNMPD_V3ONLY_CONFIG` as its own
   agent.
4. **Notification sink pinned** to `127.0.0.1:1170`. The reference
   fixture writes `trapsink`/`trap2sink`/`informsink` pointing at the
   ephemeral port of a just-bound test listener; a static config needs a
   fixed port. Bind the conformance listener on `127.0.0.1:1170` before
   starting this agent to capture the one-shot coldStart v1 trap, v2c
   trap and inform.

## Launch

    snmpd -C -f -c snmpd.conf -p snmpd.pid -Lf snmpd.log

(`-C` skips default config files, `-f` stays in the foreground — drop
`-f` to daemonize.)

## Date

2026-10-01
