# wire-golden — provenance

## Source

- Repository: `/home/dhaka/trishul/trishul-snmp` (Python reference, "trishul-snmp")
- Git revision: `1b01976356d61f508a6bbab32f232aa65a0909cd`
- Generated with `trishul_snmp` 0.6.2 (editable install in the reference
  repo's venv) — message/PDU construction patterns follow
  `tests/test_wire_values.py`, `tests/test_wire_v1.py`,
  `tests/test_wire_codec.py` and `tests/test_v3_crypto_parity.py`.

## Regeneration command

    /home/dhaka/trishul/trishul-snmp/.venv/bin/python generate.py

(The venv's editable install resolves the `trishul_snmp` import; no
PYTHONPATH tricks needed. Run from any directory — output lands next to
the script.)

## Case inventory (28 total)

- values (14): `value-integer`, `value-octet-string`, `value-null`,
  `value-object-identifier`, `value-ip-address`, `value-counter32`,
  `value-gauge32`, `value-timeticks`, `value-opaque`,
  `value-counter64`, `value-no-such-object`,
  `value-no-such-instance`, `value-end-of-mib-view`,
  `value-all-types` — every case is a v2c RESPONSE message
  (community `public`) carrying the named type as a varbind; the last
  one carries all 13 types in one varbind list.
- v1 (5): `v1-get`, `v1-getnext`, `v1-set`, `v1-response`, `v1-trap`
  (RFC 1157 trap fields: enterprise `1.3.6.1.4.1.8072`,
  agent-addr `127.0.0.1`, generic 0/coldStart, specific 0,
  timestamp 123456).
- v2c (7): `v2c-get`, `v2c-getnext`, `v2c-getbulk` (non-repeaters 1
  in the error-status field, max-repetitions 2 in the error-index
  field), `v2c-response-error` (noSuchName/2 with error-index 1),
  `v2c-inform`, `v2c-snmpv2-trap`, `v2c-report`.
- v3 (2): `v3-noauthnopriv-get` (flags 0x04),
  `v3-authnopriv-get-md5` (flags 0x05, HMAC-MD5 with the RFC 3414 A.2
  localized key of "maplesyrup" against engineID
  `000000000000000000000002`, supplied via `auth_key_localized=True`).
  Both pin engineID `000000000000000000000002`, boots 1, time 500;
  msg-id is the model's first wrap (1).

## Adaptations / caveats

- **authPriv is omitted on purpose.** The reference's AES-CFB privacy
  salt is `os.urandom(8)` (`trishul_snmp/security/usm.py`,
  `_encrypt_aes_cfb`) and the public API offers no way to pin the
  salt/IV, so an authPriv message can never be byte-reproducible. The
  Rust port should instead test AES privacy against the
  `crypto-vectors` fixtures (key-derivation parity) plus live
  `fixtures/snmpd` integration.
- **`v2c-report` is hand-assembled.** The reference's `PduType` enum has
  no REPORT entry (tag 0xA8), so the case is built with the library's
  own `ber.encode_tlv` / `asn1.encode_value` primitives using the
  standard reportPDU layout (request-id, error-status, error-index,
  varbind list — identical to any other read/write PDU). The Python
  library itself cannot *decode* this case (by design); the Rust port
  is its consumer.
- **Determinism.** All inputs are fixed literals. The v3 engine state is
  set through the `UsmModel` engine property setters, which do not arm
  the monotonic clock, so `engine_time` stays exactly 500 (verified by
  running the generator twice and diffing the output — identical).

## cryptography-version caveat

The `meta.cryptography_version` recorded in `golden.json` is 48.0.0 —
the pinned reference version. Although the vendored cases here do not
exercise AES privacy (see above), any *future* extension of this
fixture to authPriv must keep in mind: the `cryptography` package only
implements RFC 3826-compatible full-block CFB segment size from 48.0.0
onward (earlier releases defaulted to 8-bit CFB segments, producing
different ciphertext for the same key/IV). Regenerate only with
`cryptography == 48.0.0`.

## Date

2026-10-01
