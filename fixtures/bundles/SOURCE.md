# bundles — provenance

## Source

- Repository: `/home/dhaka/trishul/trishul-smi` (MIB compiler, "trishul-smi")
- Git revision: `d555140daa720b922c621932c399302fa3efb4f3`
- Source path: `/home/dhaka/trishul/trishul-smi/mibs-output/`

## Generation path

Copied verbatim from `mibs-output/` (the trishul-smi compiled-JSON
output directory). Not regenerated — the checked-in compiler output is
the canonical artifact.

## Vendored bundles (4)

| File | Module | Why |
|------|--------|-----|
| `IF-MIB.json` | IF-MIB | table-heavy core MIB (ifTable/ifXTable) |
| `SNMPv2-MIB.json` | SNMPv2-MIB | core scalar MIB (system, snmp) + notifications |
| `IPV6-TC.json` | IPV6-TC | compact types-only module (textual conventions) |
| `TEST-E2E-MIB.json` | TEST-E2E-MIB | minimal BITS + UNITS + INTEGER-enum module |

All four use bundle schema `1.1`; producer versions are the ones
recorded inside each file (0.5.3 / 0.4.6 / 0.4.6 / 0.5.3 respectively,
from different compilation passes of trishul-smi).

## TEST-E2E-MIB provenance

Compiled specifically for the Phase 6 MIB suite with the vendored
compiler at the revision above (v0.5.3):

```text
python -m trishul_smi compile TEST-E2E-MIB --mib-dir <dir> -o <out> --cache-dir ""
```

The MIB source (`TEST-E2E-MIB.mib`) is the reference's
`tests/test_mib_tsmi_e2e.py` `_TINY_MIB` verbatim: `status` (INTEGER
enum + inline `enums`), `speed` (Gauge32 with UNITS `"bits/second"`),
`flags` (BITS with inline `enums`). It exists because none of the three
vendor bundles carry a UNITS or BITS object, and this is the only
tsmi-produced fixture that exercises those render paths.

## Sidecar files

None vendored: `mibs-output/` contains per-module `*.json` files only —
no `manifest.json` and no `oid_index.json` exist there. The bundle
format treats both as optional (the Python loader,
`trishul_snmp/mib/loader.py`, discovers per-module JSON directly when
no manifest is present). If the Rust port needs a manifest/oid_index
exercise, the Python tests synthesize them by hand in
`tests/_bundle_fixtures.py` (see `write_scalar_instance_alias_bundle`);
the Rust tests do the same in `tests/common/mib.rs`.

## Date

2026-10-05
