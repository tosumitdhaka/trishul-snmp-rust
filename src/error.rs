//! Error, UnwrapOutcome, EngineReport (← errors.py)

use crate::codec::pdu::Pdu;
use crate::types::oid::InvalidOid;
use crate::types::varbind::ErrorStatus;

/// A malformed or unsupported wire-data failure (← `errors.py:ProtocolError`).
///
/// Carries the byte offset into the input where decoding failed when known.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("protocol error at offset {offset:?}: {message}")]
pub struct ProtocolError {
    /// Byte offset into the input where the failure was detected.
    pub offset: Option<usize>,
    /// Human-readable failure description.
    pub message: String,
}

impl ProtocolError {
    /// Creates a protocol error without a byte offset.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            offset: None,
            message: message.into(),
        }
    }

    /// Creates a protocol error with the byte offset of the failure.
    #[must_use]
    pub fn at(offset: usize, message: impl Into<String>) -> Self {
        Self {
            offset: Some(offset),
            message: message.into(),
        }
    }
}

/// A socket or network transport failure (← `errors.py:TransportError`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransportError {
    /// An I/O or resolution failure.
    #[error("transport failure: {0}")]
    Io(String),
    /// A receive timed out (← `RequestTimeoutError`, added: the §6 taxonomy's
    /// `Error::Timeout` is the post-retry surface; the per-receive timeout is
    /// carried here so the retry loop can distinguish it from other failures).
    #[error("SNMP request timed out waiting for a response")]
    Timeout,
}

/// A bundled-MIB load or validation failure (← `errors.py:BundleError`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BundleError {
    /// A module or bundle artifact is structurally invalid, with its path
    /// (← `errors.py:BundleValidationError`).
    #[error("bundle validation failed: {message} (path: {path})")]
    Validation { path: String, message: String },
    /// The bundle could not be loaded.
    #[error("bundle load failed: {0}")]
    Load(String),
}

/// Symbolic or numeric translation failure (← `errors.py:TranslationError`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TranslationError {
    /// An OID string or path is malformed (← `InvalidOidError`).
    #[error("invalid OID: {0}")]
    InvalidOid(#[from] InvalidOid),
    /// A symbolic identifier cannot be resolved (← `UnknownSymbolError`).
    #[error("unknown symbol: {0}")]
    UnknownSymbol(String),
    /// A numeric OID cannot be resolved (← `UnknownOidError`).
    #[error("unknown OID: {0}")]
    UnknownOid(String),
}

/// A usmStatsNotInTimeWindows REPORT's raw bytes plus the adopted peer engine
/// state (← `errors.py:EngineRecoveryReportError`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineReport {
    /// The raw REPORT message bytes.
    pub raw: Vec<u8>,
    /// The peer engine ID adopted from the REPORT.
    pub engine_id: Vec<u8>,
    /// The peer engine boots value adopted from the REPORT.
    pub engine_boots: u32,
    /// The peer engine time value adopted from the REPORT.
    pub engine_time: u32,
}

/// Typed outcome of `unwrap_message`, replacing `Option` + exception selection
/// (← usm.py:341–391, community.py:41–47).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnwrapOutcome {
    /// The message decoded and passed security checks.
    Ok(Pdu),
    /// Wrong community/user/engine: silently skip.
    NotForUs,
    /// Structurally malformed; listeners count and drop, dispatchers skip.
    Malformed(ProtocolError),
    /// HMAC mismatch; surfaces, never swallowed as `NotForUs`.
    AuthFailed,
    /// usmStatsNotInTimeWindows REPORT; the model already adopted the state.
    EngineRecoveryPending,
}

/// Top-level crate error (docs/architecture.md §6, ← errors.py).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Malformed or unsupported wire data; carries a byte offset.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    /// Bind/connect/send failures.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// Retries exhausted.
    #[error("request timed out after {attempts} attempt(s)")]
    Timeout { attempts: u8 },
    /// HMAC mismatch; `Debug` never contains key material.
    #[error("authentication failed")]
    Authentication,
    /// Engine-recovery REPORT pending adoption (see `UnwrapOutcome`).
    #[error("engine recovery pending")]
    EngineRecovery(EngineReport),
    /// A walk terminated early on an error response.
    #[error("walk aborted: {status:?} at index {index}")]
    WalkAborted { status: ErrorStatus, index: u32 },
    /// Bundle loading or validation failure.
    #[error(transparent)]
    Bundle(#[from] BundleError),
    /// Symbolic or numeric translation failure.
    #[error(transparent)]
    Translation(#[from] TranslationError),
    /// Constructor validation failure.
    #[error("invalid input: {0}")]
    InvalidInput(String),
}
