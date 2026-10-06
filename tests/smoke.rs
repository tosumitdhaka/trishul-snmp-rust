//! Smoke test: proves the library links and `VERSION` mirrors Cargo.toml.

#[test]
fn crate_version_matches_manifest() {
    assert_eq!(trishul_snmp::VERSION, env!("CARGO_PKG_VERSION"));
}

#[test]
fn lib_links() {
    // Referencing the public facade is a compile-time reachability check.
    let _version: &str = trishul_snmp::VERSION;
    let _ = _version;
}
