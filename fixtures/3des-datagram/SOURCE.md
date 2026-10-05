# fixtures/3des-datagram — vendored 3DES-EDE authPriv datagram

Provenance: generated with the reference implementation at repo rev
**1b01976** ("release: v0.6.2 — hardening and interoperability") using its
`.venv` (cryptography **48.0.0** — the pinned version whose full-block CFB
behaviour the codec parity depends on).

- `generate.py` — the exact generation script (deterministic inputs:
  engine id `80001f8804726565646572696e76657374`, boots 2, time 500,
  msg_id counter starting at 1234, GET request_id `0x01020304`,
  sysUpTime.0 TimeTicks 12345).
- `datagram.hex` — the produced authPriv (SHA-256 + 3DES-EDE) datagram.
  The 3DES salt is random and self-describing inside the datagram.
- `key-material.hex` — the 32-octet localized 3DES-EDE key material
  (`PrivKey::Localized` input for the Rust decrypt-side test).

The Rust test (`tests/usm.rs` / `tests/v3_datagram.rs`) decrypts the
vendored bytes with the key material and asserts the recovered ScopedPDU
(request_id 0x01020304, sysUpTime.0 = TimeTicks 12345), and verifies the
auth tag with the localized SHA-256 key.
