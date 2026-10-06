# tsnmp 0.1.0 Release Checklist

Status: all pre-release items verified at HEAD (`2eea907`); the 0.1.0 release
itself is **pending the owner's release decision** (see
[Owner-decision items](#owner-decision-items)).

## Pre-release checklist

| # | Item | Verified state |
|---|---|---|
| 1 | CI green on GitHub Actions | Every phase push ran the full workflow (fmt, clippy `-D warnings`, stable test, docs) green, including the **MSRV 1.88 job** (`cargo build` + `cargo test` on the 1.88 toolchain, `.github/workflows/ci.yml` `msrv`) |
| 2 | `cargo publish --dry-run` clean | Verified at HEAD: no missing files, no warnings, package metadata valid |
| 3 | Package contents curated | 98 files at HEAD (verified via `cargo package --list`); tests, fixtures, and docs are deliberately included (downstream `cargo test` needs the fixtures via `CARGO_MANIFEST_DIR`); tooling excluded via `exclude` (`.github/`, `.cortexkit/`, fixture generators `generate.py`) |
| 4 | Version | `0.1.0` in `Cargo.toml` (single source; `tsnmp version` prints it) |
| 5 | License | MIT (`Cargo.toml` + `LICENSE`) |
| 6 | README/docs current | `README.md` feature surface, `docs/cli.md` command reference, `docs/architecture.md` (incl. the §8 deviations table below) all reflect the Phase 8 surface |
| 7 | CHANGELOG present | `CHANGELOG.md` (Keep a Changelog style) with the 0.1.0 entry |
| 8 | Working tree clean | Clean at HEAD (`2eea907`), including the pre-release hardening batch and the independent review of it (ora-12) |
| 9 | Deviations table complete | `docs/architecture.md` §8 documents every deliberate divergence from the Python reference — the reviewed Python-divergence contract, extended by this batch's bounded engine tracking and `~user` bundle-path expansion rows |
| 10 | Review coverage | Independent review completed for all 8 phases (ora-4 … ora-11, each merged with GO-WITH-FIXES/NO-GO-resolved) plus the plan review; fixes landed in dedicated commits |

## Test gate (batch close)

The full local gate was run against the batch: `cargo build --all-targets`,
`cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --all --
--check`, `cargo doc --no-deps`, MSRV (`cargo +1.88 test`), and the
env-gated conformance suite (`TSNMP_SNMPD=1 cargo test --test
conformance_snmpd`) in both default-parallel and `--test-threads=1` modes.

## Owner-decision items

Pending the owner's release decision — **not yet performed**:

- [ ] Create the `v0.1.0` tag at the batch commit
- [ ] `cargo publish` (crate `trishul-snmp`, binary `tsnmp` — both names free on crates.io)
- [ ] GitHub release for `v0.1.0` (tag notes: point at the CHANGELOG 0.1.0 entry)