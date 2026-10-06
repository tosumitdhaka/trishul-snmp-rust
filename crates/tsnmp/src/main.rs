//! Thin bin: the same `tsnmp` CLI as the trishul-snmp crate.

fn main() {
    std::process::exit(trishul_snmp::cli::run());
}
