//! Native Rust SNMP toolkit: manager operations, notifications, a read-only
//! responder, and compiled-JSON MIB enrichment for SNMPv1/v2c/v3-USM.
//!
//! Rust port of the Python `trishul-snmp` reference implementation — the Python
//! library is the reference for the feature surface; the API shape is Rust-native.
//!
//! Module tree and public API are fixed in `docs/architecture.md`.

/// Crate version, mirrored from Cargo.toml.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod cli;
pub mod codec;
pub mod error;
pub mod manager;
pub mod mib;
pub mod notify;
pub mod responder;
pub mod security;
pub mod session;
pub mod target;
pub mod time;
pub mod transport;
pub mod types;
