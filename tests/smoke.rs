//! Smoke test: proves the library links and the crate version is 0.1.0.

#[test]
fn crate_version_is_0_1_0() {
    assert_eq!(trishul_snmp::VERSION, "0.1.0");
}

#[test]
fn lib_links() {
    // Referencing the public facade is a compile-time reachability check.
    let _version: &str = trishul_snmp::VERSION;
    let _ = _version;
}
