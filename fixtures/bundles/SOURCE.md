# bundles — provenance

## Source

- Repository: `/home/dhaka/trishul/trishul-smi` (MIB compiler, "trishul-smi")
- Git revision: `d555140daa720b922c621932c399302fa3efb4f3`
- Source path: `/home/dhaka/trishul/trishul-smi/mibs-output/`

## Generation path

Copied verbatim from `mibs-output/` (the trishul-smi compiled-JSON
output directory). Not regenerated — the checked-in compiler output is
the canonical artifact.

## Vendored bundles (3)

| File | Module | Why |
|------|--------|-----|
| `IF-MIB.json` | IF-MIB | table-heavy core MIB (ifTable/ifXTable) |
| `SNMPv2-MIB.json` | SNMPv2-MIB | core scalar MIB (system, snmp) + notifications |
| `IPV6-TC.json` | IPV6-TC | compact types-only module (textual conventions) |

All three use bundle schema `1.1`; producer versions are the ones
recorded inside each file (0.5.3 / 0.4.6 / 0.4.6 respectively, from
different compilation passes of trishul-smi).

## Sidecar files

None vendored: `mibs-output/` contains per-module `*.json` files only —
no `manifest.json` and no `oid_index.json` exist there. The bundle
format treats both as optional (the Python loader,
`trishul_snmp/mib/loader.py`, discovers per-module JSON directly when
no manifest is present). If the Rust port needs a manifest/oid_index
exercise, the Python tests synthesize them by hand in
`tests/_bundle_fixtures.py` (see `write_scalar_instance_alias_bundle`).

## Date

2026-10-01
