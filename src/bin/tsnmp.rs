//! Thin bin: calls trishul_snmp::cli::run() (docs/architecture.md §4).

fn main() {
    std::process::exit(trishul_snmp::cli::run());
}
