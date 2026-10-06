//! Alias crate for [`trishul_snmp`]: re-exports its entire public API.
//!
//! `tsnmp` and `trishul-snmp` are the same project — this crate exists so
//! both names on crates.io resolve to the Rust SNMP toolkit. Prefer
//! `trishul-snmp` (the canonical name); this alias tracks it version for
//! version and provides the same `tsnmp` CLI binary.

pub use trishul_snmp::*;
