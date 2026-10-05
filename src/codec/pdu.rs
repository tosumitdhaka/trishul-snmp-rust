//! Pdu, PduKind, V1TrapFields (← pdu.py)

use std::net::Ipv4Addr;

use rasn::prelude::*;
use rasn::types::{Any, Constraints, Identifier, Tag};

use crate::codec::validate::validate_trap_fields;
use crate::error::ProtocolError;
use crate::types::oid::Oid;
use crate::types::value::{SnmpValue, decode_unsigned, encode_unsigned};
use crate::types::varbind::{ErrorStatus, VarBind};

const TAG_SEQUENCE: u8 = 0x30;
const TAG_IP_ADDRESS: u8 = 0x40;
const TAG_TIMETICKS: u8 = 0x43;

/// SNMP PDU kinds, one per wire tag 0xA0–0xA8.
///
/// `Report` (0xA8) is included — the reference excluded it from its PDU tag
/// enum and paid with three duplicated hand-parsers; including it removes
/// ~90 lines of duplication (docs/architecture.md §5.3, §8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PduKind {
    GetRequest,
    GetNextRequest,
    Response,
    SetRequest,
    Trap,
    GetBulkRequest,
    InformRequest,
    SnmpV2Trap,
    Report,
}

impl PduKind {
    /// The wire tag byte (0xA0–0xA8) for this kind.
    #[must_use]
    pub fn to_raw_tag(self) -> u8 {
        0xA0 + self as u8
    }

    /// Maps a wire tag byte to a kind, if supported.
    #[must_use]
    pub fn from_raw_tag(tag: u8) -> Option<Self> {
        match tag {
            0xA0 => Some(Self::GetRequest),
            0xA1 => Some(Self::GetNextRequest),
            0xA2 => Some(Self::Response),
            0xA3 => Some(Self::SetRequest),
            0xA4 => Some(Self::Trap),
            0xA5 => Some(Self::GetBulkRequest),
            0xA6 => Some(Self::InformRequest),
            0xA7 => Some(Self::SnmpV2Trap),
            0xA8 => Some(Self::Report),
            _ => None,
        }
    }
}

/// v1 Trap-PDU (0xA4, RFC 1157) fields (← pdu.py:57–62).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V1TrapFields {
    /// enterprise OID.
    pub enterprise: Oid,
    /// agent-addr.
    pub agent_addr: Ipv4Addr,
    /// generic-trap, validated 0..=6.
    pub generic_trap: u8,
    /// specific-trap.
    pub specific_trap: i32,
    /// timestamp (TimeTicks).
    pub timestamp: u32,
}

/// A decoded/encodable SNMP PDU.
///
/// `request_id` is `u32`: negative INTEGER content on the wire is
/// reinterpreted as its unsigned image, and no reference test covers negative
/// ids (§8). `error_status`/`error_index` keep the raw wire values — they
/// double as GETBULK non-repeaters / max-repetitions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pdu {
    /// The PDU kind (wire tag).
    pub kind: PduKind,
    /// The request id.
    pub request_id: u32,
    /// Raw error-status (GETBULK non-repeaters).
    pub error_status: i32,
    /// Raw error-index (GETBULK max-repetitions).
    pub error_index: i32,
    /// The varbind list.
    pub varbinds: Vec<VarBind>,
    /// v1 Trap fields; `Some` iff `kind == Trap`.
    pub v1_trap: Option<V1TrapFields>,
}

impl Pdu {
    /// GETBULK non-repeaters: the raw `error_status` field, with negative
    /// values saturated to 0 (§5.3).
    #[must_use]
    pub fn non_repeaters(&self) -> u32 {
        u32::try_from(self.error_status).unwrap_or(0)
    }

    /// GETBULK max-repetitions: the raw `error_index` field, with negative
    /// values saturated to 0 (§5.3).
    #[must_use]
    pub fn max_repetitions(&self) -> u32 {
        u32::try_from(self.error_index).unwrap_or(0)
    }

    pub(crate) fn to_raw(&self) -> Result<RawPdu, ProtocolError> {
        if self.kind == PduKind::Trap {
            let trap = self
                .v1_trap
                .as_ref()
                .ok_or_else(|| ProtocolError::new("Trap PDU requires v1_trap fields"))?;
            validate_trap_fields(i64::from(trap.generic_trap), i64::from(trap.specific_trap))?;
            return Ok(RawPdu::Trap(RawTrapBody {
                enterprise: trap.enterprise.clone(),
                agent_addr: IpAddrWire(trap.agent_addr),
                generic_trap: i64::from(trap.generic_trap),
                specific_trap: i64::from(trap.specific_trap),
                timestamp: TimeTicksWire(trap.timestamp),
                varbinds: raw_varbinds(self.varbinds.as_slice()),
            }));
        }
        if self.v1_trap.is_some() {
            return Err(ProtocolError::new(
                "v1_trap fields are only valid for Trap PDUs",
            ));
        }
        let body = RawBody {
            request_id: i64::from(self.request_id),
            error_status: i64::from(self.error_status),
            error_index: i64::from(self.error_index),
            varbinds: raw_varbinds(self.varbinds.as_slice()),
        };
        Ok(match self.kind {
            PduKind::GetRequest => RawPdu::Get(body),
            PduKind::GetNextRequest => RawPdu::GetNext(body),
            PduKind::Response => RawPdu::Response(body),
            PduKind::SetRequest => RawPdu::Set(body),
            PduKind::Trap => unreachable!("handled above"),
            PduKind::GetBulkRequest => RawPdu::GetBulk(body),
            PduKind::InformRequest => RawPdu::Inform(body),
            PduKind::SnmpV2Trap => RawPdu::SnmpV2Trap(body),
            PduKind::Report => RawPdu::Report(body),
        })
    }
}

/// Encodes a PDU to BER bytes (← pdu.py:encode_pdu).
pub fn encode_pdu(pdu: &Pdu) -> Result<Vec<u8>, ProtocolError> {
    rasn::ber::encode(&pdu.to_raw()?).map_err(|e| ProtocolError::new(e.to_string()))
}

/// Decodes a BER-encoded PDU under DER options, with trailing-content
/// rejection (← pdu.py:decode_pdu). Tag 0xA8 (REPORT) is supported.
pub fn decode_pdu(data: &[u8]) -> Result<Pdu, ProtocolError> {
    if data.is_empty() {
        return Err(ProtocolError::new("BER tag is truncated"));
    }
    let tag = data[0];
    if !(0xA0..=0xA8).contains(&tag) {
        return Err(ProtocolError::new(format!(
            "Unsupported PDU tag 0x{tag:02x}"
        )));
    }
    let raw = crate::codec::decode_der::<RawPdu>(data)?;
    raw.into_pdu()
}

/// Converts a raw PDU error-status integer to the enum (← pdu.py:148–153).
pub fn response_error_status(status: i32) -> Result<ErrorStatus, ProtocolError> {
    ErrorStatus::from_raw(status)
        .ok_or_else(|| ProtocolError::new(format!("Unsupported SNMP error-status value {status}")))
}

/// IpAddress on the wire (tag 0x40, exactly four octets).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IpAddrWire(Ipv4Addr);

impl AsnType for IpAddrWire {
    const TAG: Tag = Tag::new(Class::Application, 0);
    const IDENTIFIER: Identifier = Identifier(Some("IpAddress"));
}

impl Decode for IpAddrWire {
    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        use rasn::de::Error as _;
        let codec = decoder.codec();
        let any = Any::decode_with_tag_and_constraints(decoder, tag, constraints)?;
        let content = any.as_bytes();
        if content.len() != 4 {
            return Err(D::Error::custom(
                "IpAddress values must contain exactly four octets",
                codec,
            ));
        }
        Ok(Self(Ipv4Addr::new(
            content[0], content[1], content[2], content[3],
        )))
    }
}

impl Encode for IpAddrWire {
    fn encode_with_tag_and_constraints<'b, EN: Encoder<'b>>(
        &self,
        encoder: &mut EN,
        _tag: Tag,
        _constraints: Constraints,
        identifier: Identifier,
    ) -> Result<(), EN::Error> {
        let mut tlv = vec![TAG_IP_ADDRESS, 0x04];
        tlv.extend_from_slice(&self.0.octets());
        encoder
            .encode_any(Tag::EOC, &Any::new(tlv), identifier)
            .map(drop)
    }
}

/// TimeTicks on the wire (tag 0x43): unsigned, minimally encoded, u32 bound
/// (← pdu.py:_decode_timeticks_from).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TimeTicksWire(u32);

impl AsnType for TimeTicksWire {
    const TAG: Tag = Tag::new(Class::Application, 3);
    const IDENTIFIER: Identifier = Identifier(Some("TimeTicks"));
}

impl Decode for TimeTicksWire {
    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        use rasn::de::Error as _;
        let codec = decoder.codec();
        let any = Any::decode_with_tag_and_constraints(decoder, tag, constraints)?;
        let value = decode_unsigned(any.as_bytes(), u64::from(u32::MAX), "TimeTicks")
            .map_err(|e| D::Error::custom(e.message, codec))?;
        Ok(Self(value as u32))
    }
}

impl Encode for TimeTicksWire {
    fn encode_with_tag_and_constraints<'b, EN: Encoder<'b>>(
        &self,
        encoder: &mut EN,
        _tag: Tag,
        _constraints: Constraints,
        identifier: Identifier,
    ) -> Result<(), EN::Error> {
        use rasn::enc::Error as _;
        let codec = encoder.codec();
        let content = encode_unsigned(u64::from(self.0), "TimeTicks")
            .map_err(|e| EN::Error::custom(e.message, codec))?;
        let mut tlv = vec![TAG_TIMETICKS];
        tlv.extend(
            crate::codec::encode_length(content.len())
                .map_err(|e| EN::Error::custom(e.message, codec))?,
        );
        tlv.extend(content);
        encoder
            .encode_any(Tag::EOC, &Any::new(tlv), identifier)
            .map(drop)
    }
}

/// Standard read/write PDU body: request-id, error-status, error-index,
/// varbind-list (used by every kind except the v1 Trap-PDU).
#[derive(AsnType, Decode, Encode)]
pub(crate) struct RawBody {
    request_id: i64,
    error_status: i64,
    error_index: i64,
    varbinds: RawVarbindList,
}

/// v1 Trap-PDU (RFC 1157) body.
#[derive(AsnType, Decode, Encode)]
pub(crate) struct RawTrapBody {
    enterprise: Oid,
    agent_addr: IpAddrWire,
    generic_trap: i64,
    specific_trap: i64,
    timestamp: TimeTicksWire,
    varbinds: RawVarbindList,
}

/// PDU choice: the variant tag (0xA0–0xA8) replaces the body's SEQUENCE tag.
///
/// SNMP PDU tags are context-class `[0]`..`[8]` implicit tags on the wire
/// (RFC 1157 / RFC 3416), not application-class.
#[derive(AsnType, Decode, Encode)]
#[rasn(choice)]
pub(crate) enum RawPdu {
    #[rasn(tag(Context, 0))]
    Get(RawBody),
    #[rasn(tag(Context, 1))]
    GetNext(RawBody),
    #[rasn(tag(Context, 2))]
    Response(RawBody),
    #[rasn(tag(Context, 3))]
    Set(RawBody),
    #[rasn(tag(Context, 4))]
    Trap(RawTrapBody),
    #[rasn(tag(Context, 5))]
    GetBulk(RawBody),
    #[rasn(tag(Context, 6))]
    Inform(RawBody),
    #[rasn(tag(Context, 7))]
    SnmpV2Trap(RawBody),
    #[rasn(tag(Context, 8))]
    Report(RawBody),
}

/// One varbind: OBJECT IDENTIFIER + value.
#[derive(AsnType, Decode, Encode)]
pub(crate) struct RawVarbind {
    oid: Oid,
    value: SnmpValue,
}

/// SEQUENCE OF `RawVarbind` with a manual, strict codec.
///
/// rasn's derived `Vec<T>` decode treats a failing element as the end of the
/// sequence and silently *drops* it — a malformed varbind would disappear
/// instead of failing the message. The reference errors instead
/// (pdu.py:_decode_varbind_list). This shim walks the list content strictly
/// and decodes each element under its own DER decoder, so element framing
/// errors surface with the reference's messages.
pub(crate) struct RawVarbindList(pub(crate) Vec<RawVarbind>);

impl AsnType for RawVarbindList {
    const TAG: Tag = Tag::SEQUENCE;
    const IDENTIFIER: Identifier = Identifier::SEQUENCE_OF;
}

impl Decode for RawVarbindList {
    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        _tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        use rasn::de::Error as _;
        let codec = decoder.codec();
        let any = Any::decode_with_tag_and_constraints(decoder, Tag::EOC, constraints)?;
        let tlv = any.as_bytes();
        let (tag, content, end) =
            crate::codec::decode_tlv(tlv, 0).map_err(|e| D::Error::custom(e.message, codec))?;
        if tag != TAG_SEQUENCE {
            return Err(D::Error::custom(
                format!("Expected VarBindList SEQUENCE, found 0x{tag:02x}"),
                codec,
            ));
        }
        if end != tlv.len() {
            return Err(D::Error::custom("Unexpected trailing BER content", codec));
        }

        let mut varbinds = Vec::new();
        let mut offset = 0;
        while offset < content.len() {
            let (element_tag, _element_content, next) =
                crate::codec::decode_tlv(content, offset)
                    .map_err(|e| D::Error::custom(e.message, codec))?;
            if element_tag != TAG_SEQUENCE {
                return Err(D::Error::custom(
                    format!("Expected VarBind SEQUENCE, found 0x{element_tag:02x}"),
                    codec,
                ));
            }
            let element_tlv = &content[offset..next];
            let mut sub =
                rasn::ber::de::Decoder::new(element_tlv, rasn::ber::de::DecoderOptions::der());
            let varbind =
                RawVarbind::decode(&mut sub).map_err(|e| D::Error::custom(e.to_string(), codec))?;
            if !sub.remaining().is_empty() {
                return Err(D::Error::custom("Unexpected trailing BER content", codec));
            }
            varbinds.push(varbind);
            offset = next;
        }
        Ok(Self(varbinds))
    }
}

impl Encode for RawVarbindList {
    fn encode_with_tag_and_constraints<'b, EN: Encoder<'b>>(
        &self,
        encoder: &mut EN,
        _tag: Tag,
        _constraints: Constraints,
        identifier: Identifier,
    ) -> Result<(), EN::Error> {
        use rasn::enc::Error as _;
        let codec = encoder.codec();
        let mut content = Vec::new();
        for varbind in &self.0 {
            content.extend(
                rasn::ber::encode(varbind).map_err(|e| EN::Error::custom(e.to_string(), codec))?,
            );
        }
        let mut tlv = vec![TAG_SEQUENCE];
        tlv.extend(
            crate::codec::encode_length(content.len())
                .map_err(|e| EN::Error::custom(e.message, codec))?,
        );
        tlv.extend(content);
        encoder
            .encode_any(Tag::EOC, &Any::new(tlv), identifier)
            .map(drop)
    }
}

impl RawPdu {
    pub(crate) fn into_pdu(self) -> Result<Pdu, ProtocolError> {
        Ok(match self {
            RawPdu::Get(body) => body.into_pdu(PduKind::GetRequest),
            RawPdu::GetNext(body) => body.into_pdu(PduKind::GetNextRequest),
            RawPdu::Response(body) => body.into_pdu(PduKind::Response),
            RawPdu::Set(body) => body.into_pdu(PduKind::SetRequest),
            RawPdu::Trap(body) => body.into_pdu()?,
            RawPdu::GetBulk(body) => body.into_pdu(PduKind::GetBulkRequest),
            RawPdu::Inform(body) => body.into_pdu(PduKind::InformRequest),
            RawPdu::SnmpV2Trap(body) => body.into_pdu(PduKind::SnmpV2Trap),
            RawPdu::Report(body) => body.into_pdu(PduKind::Report),
        })
    }
}

impl RawBody {
    fn into_pdu(self, kind: PduKind) -> Pdu {
        Pdu {
            kind,
            request_id: self.request_id as u32,
            error_status: self.error_status as i32,
            error_index: self.error_index as i32,
            varbinds: self.varbinds.0.into_iter().map(VarBind::from).collect(),
            v1_trap: None,
        }
    }
}

impl RawTrapBody {
    fn into_pdu(self) -> Result<Pdu, ProtocolError> {
        let (generic_trap, specific_trap) =
            validate_trap_fields(self.generic_trap, self.specific_trap)?;
        Ok(Pdu {
            kind: PduKind::Trap,
            request_id: 0,
            error_status: 0,
            error_index: 0,
            varbinds: self.varbinds.0.into_iter().map(VarBind::from).collect(),
            v1_trap: Some(V1TrapFields {
                enterprise: self.enterprise,
                agent_addr: self.agent_addr.0,
                generic_trap,
                specific_trap,
                timestamp: self.timestamp.0,
            }),
        })
    }
}

impl From<RawVarbind> for VarBind {
    fn from(raw: RawVarbind) -> Self {
        Self::new(raw.oid, raw.value)
    }
}

impl From<&VarBind> for RawVarbind {
    fn from(varbind: &VarBind) -> Self {
        Self {
            oid: varbind.oid.clone(),
            value: varbind.value.clone(),
        }
    }
}

fn raw_varbinds(varbinds: &[VarBind]) -> RawVarbindList {
    RawVarbindList(varbinds.iter().map(RawVarbind::from).collect())
}
