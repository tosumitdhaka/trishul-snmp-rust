//! VarBind, OidMatch, Response, ErrorStatus (← types.py:188–238)

use crate::types::oid::Oid;
use crate::types::value::SnmpValue;

/// SNMP PDU error-status values (RFC 3416 §11.5, ← types.py:13–38).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorStatus {
    NoError = 0,
    TooBig = 1,
    NoSuchName = 2,
    BadValue = 3,
    ReadOnly = 4,
    GenErr = 5,
    NoAccess = 6,
    WrongType = 7,
    WrongLength = 8,
    WrongEncoding = 9,
    WrongValue = 10,
    NoCreation = 11,
    InconsistentValue = 12,
    ResourceUnavailable = 13,
    CommitFailed = 14,
    UndoFailed = 15,
    AuthorizationError = 16,
    NotWritable = 17,
    InconsistentName = 18,
}

impl ErrorStatus {
    /// The raw wire value of this status.
    #[must_use]
    pub fn as_raw(self) -> i32 {
        self as i32
    }

    /// Lower-case label (`"no_such_name"`, …), ← the reference's `label`
    /// property (types.py:36–38).
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::NoError => "no_error",
            Self::TooBig => "too_big",
            Self::NoSuchName => "no_such_name",
            Self::BadValue => "bad_value",
            Self::ReadOnly => "read_only",
            Self::GenErr => "gen_err",
            Self::NoAccess => "no_access",
            Self::WrongType => "wrong_type",
            Self::WrongLength => "wrong_length",
            Self::WrongEncoding => "wrong_encoding",
            Self::WrongValue => "wrong_value",
            Self::NoCreation => "no_creation",
            Self::InconsistentValue => "inconsistent_value",
            Self::ResourceUnavailable => "resource_unavailable",
            Self::CommitFailed => "commit_failed",
            Self::UndoFailed => "undo_failed",
            Self::AuthorizationError => "authorization_error",
            Self::NotWritable => "not_writable",
            Self::InconsistentName => "inconsistent_name",
        }
    }

    /// Maps a raw PDU error-status integer to the enum, if it is one of the
    /// 19 defined values (← `pdu.py:response_error_status`).
    #[must_use]
    pub fn from_raw(raw: i32) -> Option<Self> {
        match raw {
            0 => Some(Self::NoError),
            1 => Some(Self::TooBig),
            2 => Some(Self::NoSuchName),
            3 => Some(Self::BadValue),
            4 => Some(Self::ReadOnly),
            5 => Some(Self::GenErr),
            6 => Some(Self::NoAccess),
            7 => Some(Self::WrongType),
            8 => Some(Self::WrongLength),
            9 => Some(Self::WrongEncoding),
            10 => Some(Self::WrongValue),
            11 => Some(Self::NoCreation),
            12 => Some(Self::InconsistentValue),
            13 => Some(Self::ResourceUnavailable),
            14 => Some(Self::CommitFailed),
            15 => Some(Self::UndoFailed),
            16 => Some(Self::AuthorizationError),
            17 => Some(Self::NotWritable),
            18 => Some(Self::InconsistentName),
            _ => None,
        }
    }
}

/// Resolved view of a numeric OID against the loaded bundle
/// (← types.py:188–208).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OidMatch {
    /// The queried numeric OID.
    pub oid: Oid,
    /// The MIB module containing the match.
    pub module: String,
    /// The matched symbol name.
    pub symbol: String,
    /// The longest matching prefix OID.
    pub matched_oid: Oid,
    /// Arc suffix past the matched prefix (empty when exact).
    pub suffix: Oid,
    /// Producer class label (`objecttype`, `moduleidentity`, `objectidentifier`,
    /// `notificationtype`, …) (← the reference's `class_name`).
    pub class_name: Option<String>,
    /// `OBJECT-TYPE`, `MODULE-IDENTITY`, `OBJECT IDENTIFIER`,
    /// `NOTIFICATION-TYPE`, … (← the reference's `object_type`).
    pub object_type: Option<String>,
    /// `scalar`, `table`, `column`, … (← `nodetype`).
    pub nodetype: Option<String>,
}

impl OidMatch {
    /// `MODULE::symbol[.suffix]` form, ← the `symbolic` property
    /// (types.py:201–207).
    #[must_use]
    pub fn symbolic(&self) -> String {
        let base = format!("{}::{}", self.module, self.symbol);
        if self.suffix.arcs().is_empty() {
            base
        } else {
            format!("{base}.{}", self.suffix.display())
        }
    }
}

/// Public varbind model. The enrichment fields are `None` until a MIB bundle
/// renders them (← types.py:210–228; render.py:19–60).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VarBind {
    /// The varbind's OID.
    pub oid: Oid,
    /// The varbind's value.
    pub value: SnmpValue,
    /// Bundle resolution, when loaded (Python field `match`, renamed).
    pub matched: Option<OidMatch>,
    /// Rendered symbolic name, when enriched.
    pub display_name: Option<String>,
    /// Rendered value text, when enriched.
    pub display_value: Option<String>,
    /// Enum/BITS label, when enriched.
    pub enum_label: Option<String>,
    /// Units suffix, when enriched.
    pub units: Option<String>,
}

impl VarBind {
    /// Creates a varbind with no enrichment.
    #[must_use]
    pub fn new(oid: Oid, value: SnmpValue) -> Self {
        Self {
            oid,
            value,
            matched: None,
            display_name: None,
            display_value: None,
            enum_label: None,
            units: None,
        }
    }

    /// Dotted-string form of the OID, ← the `oid_str` property (types.py:222–224).
    #[must_use]
    pub fn oid_str(&self) -> String {
        self.oid.display()
    }

    /// Type name of the value (`"integer"`, `"octet-string"`, …), ← the
    /// `value_type` property (types.py:226–228).
    #[must_use]
    pub fn value_type(&self) -> &'static str {
        self.value.type_name()
    }
}

/// Public manager response model (← types.py:231–238).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    /// The request id echoed by the agent.
    pub request_id: u32,
    /// The response error status.
    pub error_status: ErrorStatus,
    /// The error index (1-based into the varbinds).
    pub error_index: u32,
    /// The response varbinds.
    pub varbinds: Vec<VarBind>,
}
