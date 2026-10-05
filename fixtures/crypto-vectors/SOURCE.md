# crypto-vectors — provenance

## Source

- Repository: `/home/dhaka/trishul/trishul-snmp` (Python reference, "trishul-snmp")
- Git revision: `1b01976356d61f508a6bbab32f232aa65a0909cd`
- Source file: `tests/test_v3_crypto_parity.py`

## Groups

### `[[netsnmp_aes]]` — net-snmp 5.9.4 localized privacy keys (5 vectors)

- Source lines: 52–87 (constants `_NET_SNMP_ENGINE_ID`,
  `_NET_SNMP_AUTH_PASSWORD`, `_NET_SNMP_PRIV_PASSWORD`,
  `_NET_SNMP_AES_VECTORS`) and 235–267 (the asserting test
  `test_net_snmp_aes192_256_priv_key_vectors`).
- Fields carried: engine id (`_NET_SNMP_ENGINE_ID`, line 55), auth and
  priv passphrases (lines 56–57), auth/priv protocol pairs and expected
  localized privacy keys (`_NET_SNMP_AES_VECTORS`, lines 59–87).
- The test derives the key via `UsmModel._priv_key(engine_id)` and
  asserts byte-equality with `bytes.fromhex(expected_hex)` plus the
  protocol's key length. The literals are net-snmp 5.9.4
  persistent-store ground truth (see issue #30 in the reference repo).

### `[[reeder_3des_appendix_b]]` — draft-reeder Appendix B vectors (2 vectors)

- Source lines: 374–419 (constants `_3DES_APPENDIX_B`,
  `_APPENDIX_B_ENGINE_ID` and the asserting test
  `test_3des_short_digest_chain_matches_draft_appendix_b`).
- Fields carried: engine id `000000000000000000000002` (line 389),
  password `maplesyrup` (line 413), MD5 chain (32 octets, line 381) and
  SHA-1 chain (full 40-octet draft string, lines 384–387).
- The test asserts `key == bytes.fromhex(expected_hex)[:32]`; the TOML
  preserves the full draft literal in `chain_hex` plus the truncation
  length in `key_material_octets`.
- The draft defines no IV/salt/plaintext/ciphertext for these vectors
  and neither does the test — the chain/key material is everything the
  source asserts.

## Extraction method

Manual transcription of the literal constants (byte fields converted
to lowercase hex without `0x` prefix, passphrases kept as strings).
No value was computed or re-derived.

## Date

2026-10-01
