//! Native Rust SNMP toolkit: manager operations, notifications, a read-only
//! responder, and compiled-JSON MIB enrichment for SNMPv1/v2c/v3-USM.
//!
//! Rust port of the Python `trishul-snmp` reference implementation — the Python
//! library is the reference for the feature surface; the API shape is Rust-native.
//!
//! Module tree and public API are fixed in `docs/architecture.md`.
//!
//! # Ergonomic imports
//!
//! The primary types are re-exported at the crate root:
//!
//! ```
//! #![allow(unused_imports)]
//! # fn main() {}
//! use trishul_snmp::{
//!     decode_notification, Error, MibBundle, Manager, NotificationListener, Notifier, Oid,
//!     SnmpResponder, SnmpValue, Target, V1Config, V2cConfig, V3Config, VarBind, WalkOptions,
//! };
//! ```

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

pub use crate::error::Error;
pub use crate::manager::walk::WalkOptions;
pub use crate::manager::{Manager, V1Config, V2cConfig};
pub use crate::mib::MibBundle;
pub use crate::notify::decode_notification;
pub use crate::notify::listener::NotificationListener;
pub use crate::notify::sender::Notifier;
pub use crate::responder::SnmpResponder;
pub use crate::security::usm::V3Config;
pub use crate::target::Target;
pub use crate::types::oid::Oid;
pub use crate::types::value::SnmpValue;
pub use crate::types::varbind::VarBind;
