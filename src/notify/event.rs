//! NotificationEvent + Serialize (← notify/events.py)
//!
//! The structured inbound notification model. `Serialize` is implemented over
//! [`NotificationEvent::to_dict`], which reproduces the reference's
//! `to_dict()` byte-for-byte (test_notification_to_dict.py asserts the shape):
//! always-present fields serialize as `null` when absent, v3/v1-only fields are
//! omitted when absent, byte fields are hex-encoded, and varbinds / member
//! bindings are rendered as the reference's dicts.
//!
//! MIB enrichment (`notification_name`, `notification_description`,
//! `member_bindings`) is populated when a bundle is supplied; without a
//! bundle the fields stay `None`/empty, matching the reference.

use std::net::SocketAddr;

use serde::Serialize;

use crate::codec::message::{SnmpMessage, decode_message};
use crate::codec::pdu::{Pdu, PduKind};
use crate::error::{Error, ProtocolError};
use crate::mib::{MibBundle, MibMemberRef};
use crate::notify::v3_path::{V3NotificationEnvelope, decode_v3_notification_message};
use crate::security::usm::{UsmModel, UsmUser};
use crate::time::{SystemClock, SystemRng};
use crate::types::oid::Oid;
use crate::types::value::SnmpValue;
use crate::types::varbind::VarBind;

/// The sysUpTime.0 instance OID.
const SYS_UPTIME_INSTANCE_OID: [u32; 9] = [1, 3, 6, 1, 2, 1, 1, 3, 0];
/// The snmpTrapOID.0 instance OID.
const SNMP_TRAP_OID_INSTANCE_OID: [u32; 11] = [1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0];

/// The `pdu_type` label for a notification PDU kind (events.py:24–27).
#[must_use]
pub fn pdu_type_name(kind: PduKind) -> Option<&'static str> {
    match kind {
        PduKind::Trap => Some("trap"),
        PduKind::SnmpV2Trap => Some("snmpv2-trap"),
        PduKind::InformRequest => Some("inform-request"),
        _ => None,
    }
}

/// A declared notification member paired with its received varbind
/// (events.py:33–43). Populated from a loaded bundle; without a bundle the
/// list is always empty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotificationMemberBinding {
    /// `MODULE::symbol` form of the declared member.
    pub symbolic: String,
    /// The received varbind bound to this member, if any.
    pub varbind: Option<VarBind>,
}

impl NotificationMemberBinding {
    /// The declared member's symbolic name (events.py:41–43).
    #[must_use]
    pub fn symbolic(&self) -> &str {
        &self.symbolic
    }
}

/// Structured inbound notification event (events.py:45–157).
///
/// Field-by-field parity with the reference dataclass; `community` keeps the
/// bytewise form (locked decision) and is decoded to a string only at
/// serialization time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotificationEvent {
    /// The PDU request id.
    pub request_id: u32,
    /// v1/v2c community (bytewise); `None` for v3.
    pub community: Option<Vec<u8>>,
    /// The sending peer address; `None` for offline decodes.
    pub source_address: Option<SocketAddr>,
    /// `"trap"` | `"snmpv2-trap"` | `"inform-request"`.
    pub pdu_type: String,
    /// The notification varbinds (already enriched per §5.2 when a bundle is
    /// present).
    pub varbinds: Vec<VarBind>,
    /// The `snmpTrapOID.0` value, when carried.
    pub notification_oid: Option<Oid>,
    /// `MODULE::symbol` of the notification, when a bundle resolves it.
    pub notification_name: Option<String>,
    /// The NOTIFICATION-TYPE description, when a bundle resolves it.
    pub notification_description: Option<String>,
    /// The `sysUpTime.0` value, when carried.
    pub uptime: Option<u32>,
    /// Declared member bindings, when a bundle resolves the notification.
    pub member_bindings: Vec<NotificationMemberBinding>,
    /// `"3"` for v3 events, `None` otherwise.
    pub snmp_version: Option<String>,
    /// v3 user name.
    pub username: Option<String>,
    /// v3 security level label.
    pub security_level: Option<String>,
    /// v3 ScopedPDU contextEngineID.
    pub context_engine_id: Option<Vec<u8>>,
    /// v3 ScopedPDU contextName.
    pub context_name: Option<Vec<u8>>,
    /// v3 authoritative engine ID.
    pub authoritative_engine_id: Option<Vec<u8>>,
    /// v3 authoritative engine boots.
    pub authoritative_engine_boots: Option<u32>,
    /// v3 authoritative engine time.
    pub authoritative_engine_time: Option<u32>,
    /// v1 Trap-PDU enterprise.
    pub enterprise: Option<Oid>,
    /// v1 Trap-PDU agent address (dotted string).
    pub agent_addr: Option<String>,
    /// v1 Trap-PDU generic trap.
    pub generic_trap: Option<i32>,
    /// v1 Trap-PDU specific trap.
    pub specific_trap: Option<i32>,
    /// v1 Trap-PDU timestamp.
    pub timestamp: Option<u32>,
}

impl NotificationEvent {
    /// The source host, when a source address is present.
    #[must_use]
    pub fn source_host(&self) -> Option<String> {
        self.source_address.map(|addr| addr.ip().to_string())
    }

    /// The source port, when a source address is present.
    #[must_use]
    pub fn source_port(&self) -> Option<u16> {
        self.source_address.map(|addr| addr.port())
    }

    /// Whether this event is an inform.
    #[must_use]
    pub fn is_inform(&self) -> bool {
        self.pdu_type == "inform-request"
    }

    /// Builds the JSON-safe dict representation of this event, matching the
    /// reference's `to_dict()` shape (events.py:94–157).
    #[must_use]
    pub fn to_dict(&self) -> serde_json::Value {
        let mut payload = serde_json::Map::new();
        payload.insert("request_id".to_string(), serde_json::json!(self.request_id));
        payload.insert(
            "community".to_string(),
            opt_string(self.community.as_deref().map(community_to_string)),
        );
        payload.insert("source_host".to_string(), opt_string(self.source_host()));
        payload.insert(
            "source_port".to_string(),
            self.source_port()
                .map(|p| serde_json::json!(p))
                .unwrap_or(serde_json::Value::Null),
        );
        payload.insert("pdu_type".to_string(), serde_json::json!(self.pdu_type));
        payload.insert(
            "notification_oid".to_string(),
            opt_string(self.notification_oid.as_ref().map(Oid::display)),
        );
        payload.insert(
            "notification_name".to_string(),
            opt_string(self.notification_name.clone()),
        );
        payload.insert(
            "notification_description".to_string(),
            opt_string(self.notification_description.clone()),
        );
        payload.insert(
            "uptime".to_string(),
            self.uptime
                .map(|v| serde_json::json!(v))
                .unwrap_or(serde_json::Value::Null),
        );
        payload.insert(
            "varbinds".to_string(),
            serde_json::Value::Array(self.varbinds.iter().map(varbind_to_dict).collect()),
        );
        payload.insert(
            "member_bindings".to_string(),
            serde_json::Value::Array(
                self.member_bindings
                    .iter()
                    .map(member_binding_to_dict)
                    .collect(),
            ),
        );
        // v1 Trap-PDU fields, present only when the source is a v1 trap.
        if let Some(enterprise) = &self.enterprise {
            payload.insert(
                "enterprise".to_string(),
                serde_json::json!(enterprise.display()),
            );
        }
        if let Some(agent_addr) = &self.agent_addr {
            payload.insert("agent_addr".to_string(), serde_json::json!(agent_addr));
        }
        if let Some(generic_trap) = self.generic_trap {
            payload.insert("generic_trap".to_string(), serde_json::json!(generic_trap));
        }
        if let Some(specific_trap) = self.specific_trap {
            payload.insert(
                "specific_trap".to_string(),
                serde_json::json!(specific_trap),
            );
        }
        if let Some(timestamp) = self.timestamp {
            payload.insert("timestamp".to_string(), serde_json::json!(timestamp));
        }
        // v3 fields, present only for v3 events.
        if let Some(snmp_version) = &self.snmp_version {
            payload.insert("snmp_version".to_string(), serde_json::json!(snmp_version));
        }
        if let Some(username) = &self.username {
            payload.insert("username".to_string(), serde_json::json!(username));
        }
        if let Some(security_level) = &self.security_level {
            payload.insert(
                "security_level".to_string(),
                serde_json::json!(security_level),
            );
        }
        if let Some(context_engine_id) = &self.context_engine_id {
            payload.insert(
                "context_engine_id".to_string(),
                serde_json::json!(hex(context_engine_id)),
            );
        }
        if let Some(context_name) = &self.context_name {
            payload.insert(
                "context_name".to_string(),
                serde_json::json!(hex(context_name)),
            );
        }
        if let Some(authoritative_engine_id) = &self.authoritative_engine_id {
            payload.insert(
                "authoritative_engine_id".to_string(),
                serde_json::json!(hex(authoritative_engine_id)),
            );
        }
        if let Some(boots) = self.authoritative_engine_boots {
            payload.insert(
                "authoritative_engine_boots".to_string(),
                serde_json::json!(boots),
            );
        }
        if let Some(time) = self.authoritative_engine_time {
            payload.insert(
                "authoritative_engine_time".to_string(),
                serde_json::json!(time),
            );
        }
        serde_json::Value::Object(payload)
    }
}

impl Serialize for NotificationEvent {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // JSON parity is the contract: the reference's to_dict() shape is
        // reproduced exactly, and any serde target (JSON, etc.) sees the same
        // dict.
        serde_json::Value::serialize(&self.to_dict(), serializer)
    }
}

/// Converts a low-level v1/v2c notification message into the public event
/// model (events.py:160–173). MIB enrichment (names, member bindings) applies
/// when a bundle is supplied.
pub fn notification_event_from_message(
    message: &SnmpMessage,
    source_address: Option<SocketAddr>,
    bundle: Option<&MibBundle>,
) -> Result<NotificationEvent, ProtocolError> {
    notification_event_from_pdu(
        &message.pdu,
        message.pdu.request_id,
        Some(message.community.clone()),
        source_address,
        bundle,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
}

/// Converts a decoded v3 notification envelope into the public event model
/// (events.py:176–197).
pub fn notification_event_from_v3_envelope(
    envelope: &V3NotificationEnvelope,
    source_address: Option<SocketAddr>,
    bundle: Option<&MibBundle>,
) -> Result<NotificationEvent, ProtocolError> {
    // Strict UTF-8, matching the reference's `.decode("utf-8")` (events.py:
    // 190): a non-UTF-8 username raises instead of being lossily replaced.
    // (Unreachable through the listener/offline paths, since the envelope only
    // exists for a user whose name already matched the configured UTF-8 user.)
    let username = String::from_utf8(envelope.view.usm_params.username.clone())
        .map_err(|_| ProtocolError::new("username is not valid UTF-8"))?;
    notification_event_from_pdu(
        &envelope.pdu,
        envelope.pdu.request_id,
        None,
        source_address,
        bundle,
        Some("3".to_string()),
        Some(username),
        Some(envelope.security_level.clone()),
        Some(envelope.context_engine_id.clone()),
        Some(envelope.context_name.clone()),
        Some(envelope.view.usm_params.engine_id.clone()),
        Some(envelope.view.usm_params.engine_boots.max(0) as u32),
        Some(envelope.view.usm_params.engine_time.max(0) as u32),
    )
}

/// Decodes a BER-encoded trap or inform message (events.py:200–226).
///
/// When `user` is omitted, the SNMPv2c path is used. Supplying `user=...`
/// switches the function to strict SNMPv3 USM decode with a fresh one-shot
/// codec.
pub fn decode_notification(
    data: &[u8],
    source_address: Option<SocketAddr>,
    user: Option<&UsmUser>,
    bundle: Option<&MibBundle>,
) -> Result<NotificationEvent, Error> {
    match user {
        None => {
            let message = decode_message(data)?;
            Ok(notification_event_from_message(
                &message,
                source_address,
                bundle,
            )?)
        }
        Some(user) => {
            let decoded = crate::notify::v3_path::V3DecodedDatagram::decode(data)?;
            let codec = UsmModel::new(
                user.clone(),
                Vec::new(),
                None,
                std::sync::Arc::new(SystemClock),
                std::sync::Arc::new(SystemRng),
            );
            match decode_v3_notification_message(&decoded, user, &codec)? {
                Some(envelope) => Ok(notification_event_from_v3_envelope(
                    &envelope,
                    source_address,
                    bundle,
                )?),
                None => Err(Error::Protocol(ProtocolError::new(
                    "Message is not a valid SNMPv3 trap or inform for the configured user",
                ))),
            }
        }
    }
}

/// The shared event builder (events.py:229–295).
#[allow(clippy::too_many_arguments)]
fn notification_event_from_pdu(
    pdu: &Pdu,
    request_id: u32,
    community: Option<Vec<u8>>,
    source_address: Option<SocketAddr>,
    bundle: Option<&MibBundle>,
    snmp_version: Option<String>,
    username: Option<String>,
    security_level: Option<String>,
    context_engine_id: Option<Vec<u8>>,
    context_name: Option<Vec<u8>>,
    authoritative_engine_id: Option<Vec<u8>>,
    authoritative_engine_boots: Option<u32>,
    authoritative_engine_time: Option<u32>,
) -> Result<NotificationEvent, ProtocolError> {
    let pdu_type = pdu_type_name(pdu.kind).ok_or_else(|| {
        ProtocolError::new(format!("Unsupported notification PDU type: {:?}", pdu.kind))
    })?;

    // Enrichment: with a bundle the varbinds carry symbolic names, enum
    // labels, and units; without one only the raw display string is set
    // (render.py:19–60).
    let varbinds = crate::mib::render::enrich_varbinds(bundle, pdu.varbinds.clone());
    let notification_oid = extract_notification_oid(&varbinds);
    let uptime = extract_uptime(&varbinds);
    let (notification_name, notification_description, member_bindings) =
        notification_metadata(bundle, notification_oid.as_ref(), &varbinds);

    let (enterprise, agent_addr, generic_trap, specific_trap, timestamp) = match pdu.kind {
        PduKind::Trap => {
            let trap = pdu
                .v1_trap
                .as_ref()
                .ok_or_else(|| ProtocolError::new("Trap PDU requires v1_trap fields"))?;
            (
                Some(trap.enterprise.clone()),
                Some(trap.agent_addr.to_string()),
                Some(i32::from(trap.generic_trap)),
                Some(trap.specific_trap),
                Some(trap.timestamp),
            )
        }
        _ => (None, None, None, None, None),
    };

    Ok(NotificationEvent {
        request_id,
        community,
        source_address,
        pdu_type: pdu_type.to_string(),
        varbinds,
        notification_oid,
        notification_name,
        notification_description,
        uptime,
        member_bindings,
        snmp_version,
        username,
        security_level,
        context_engine_id,
        context_name,
        authoritative_engine_id,
        authoritative_engine_boots,
        authoritative_engine_time,
        enterprise,
        agent_addr,
        generic_trap,
        specific_trap,
        timestamp,
    })
}

/// Resolves the notification metadata (name, description, member bindings)
/// from the loaded bundle (events.py:315–341). Without a bundle, or when the
/// notification OID does not resolve exactly to a `NOTIFICATION-TYPE`, the
/// name alone (or nothing) is produced.
fn notification_metadata(
    bundle: Option<&MibBundle>,
    notification_oid: Option<&Oid>,
    varbinds: &[VarBind],
) -> (
    Option<String>,
    Option<String>,
    Vec<NotificationMemberBinding>,
) {
    let (Some(bundle), Some(notification_oid)) = (bundle, notification_oid) else {
        return (None, None, Vec::new());
    };
    let match_ = match bundle.lookup(notification_oid) {
        Ok(match_) => match_,
        Err(_) => return (None, None, Vec::new()),
    };
    if match_.matched_oid != *notification_oid || !match_.suffix.arcs().is_empty() {
        return (
            Some(bundle.display_symbolic_from_match(&match_)),
            None,
            Vec::new(),
        );
    }

    let notification_name = bundle.display_symbolic_from_match(&match_);
    let notification_node = bundle.resolve_node(&match_.module, &match_.symbol);
    let Some(node) = notification_node else {
        return (Some(notification_name), None, Vec::new());
    };
    if node.object_type != "NOTIFICATION-TYPE" {
        return (Some(notification_name), None, Vec::new());
    }
    (
        Some(notification_name),
        node.description.clone(),
        build_member_bindings(&node.members, varbinds),
    )
}

/// Binds declared notification members to the received payload varbinds
/// (events.py:348–367). The auto sysUpTime.0 / snmpTrapOID.0 varbinds are
/// excluded; each declared member binds to the payload varbind at its index
/// (or `None` when the sender omitted it).
fn build_member_bindings(
    declared_members: &Option<Vec<MibMemberRef>>,
    varbinds: &[VarBind],
) -> Vec<NotificationMemberBinding> {
    let Some(declared) = declared_members else {
        return Vec::new();
    };
    if declared.is_empty() {
        return Vec::new();
    }
    let payload_varbinds: Vec<&VarBind> = varbinds
        .iter()
        .filter(|varbind| {
            varbind.oid.arcs() != SYS_UPTIME_INSTANCE_OID
                && varbind.oid.arcs() != SNMP_TRAP_OID_INSTANCE_OID
        })
        .collect();
    declared
        .iter()
        .enumerate()
        .map(|(index, member)| NotificationMemberBinding {
            symbolic: member.symbolic(),
            varbind: payload_varbinds
                .get(index)
                .map(|varbind| (*varbind).clone()),
        })
        .collect()
}

/// The `snmpTrapOID.0` ObjectIdentifier value, if carried (events.py:298–305).
fn extract_notification_oid(varbinds: &[VarBind]) -> Option<Oid> {
    varbinds.iter().find_map(|varbind| {
        if varbind.oid.arcs() == SNMP_TRAP_OID_INSTANCE_OID
            && let SnmpValue::ObjectIdentifier(oid) = &varbind.value
        {
            Some(oid.clone())
        } else {
            None
        }
    })
}

/// The `sysUpTime.0` TimeTicks value, if carried (events.py:308–312).
fn extract_uptime(varbinds: &[VarBind]) -> Option<u32> {
    varbinds.iter().find_map(|varbind| {
        if varbind.oid.arcs() == SYS_UPTIME_INSTANCE_OID
            && let SnmpValue::TimeTicks(value) = varbind.value
        {
            Some(value)
        } else {
            None
        }
    })
}

/// The reference's community decoding (message.py:95–97): UTF-8 first, then
/// latin-1 (each byte becomes the codepoint with that value).
fn community_to_string(community: &[u8]) -> String {
    match std::str::from_utf8(community) {
        Ok(text) => text.to_string(),
        Err(_) => community.iter().map(|&byte| char::from(byte)).collect(),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn opt_string(value: Option<String>) -> serde_json::Value {
    value
        .map(serde_json::Value::String)
        .unwrap_or(serde_json::Value::Null)
}

/// The reference's varbind dict (events.py:110–118): `oid`, `display_name`,
/// `value_type`, `value`.
fn varbind_to_dict(varbind: &VarBind) -> serde_json::Value {
    serde_json::json!({
        "oid": varbind.oid_str(),
        "display_name": varbind.display_name,
        "value_type": varbind.value_type(),
        "value": varbind.display_value,
    })
}

/// The reference's member-binding dict (events.py:119–129): `symbolic`, `oid`,
/// `value_type`, `value`.
fn member_binding_to_dict(binding: &NotificationMemberBinding) -> serde_json::Value {
    match &binding.varbind {
        Some(varbind) => serde_json::json!({
            "symbolic": binding.symbolic,
            "oid": varbind.oid_str(),
            "value_type": varbind.value_type(),
            "value": varbind.display_value,
        }),
        None => serde_json::json!({
            "symbolic": binding.symbolic,
            "oid": serde_json::Value::Null,
            "value_type": serde_json::Value::Null,
            "value": serde_json::Value::Null,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::message::SnmpVersion;
    use crate::codec::pdu::V1TrapFields;
    use crate::security::usm::kdf::{AuthProtocol, PrivProtocol};
    use crate::security::usm::{AuthKey, PrivKey};
    use crate::types::oid::Oid;
    use std::net::Ipv4Addr;

    fn oid(arcs: &[u32]) -> Oid {
        Oid::from_arcs(arcs).unwrap()
    }

    fn trap_message() -> SnmpMessage {
        SnmpMessage {
            version: SnmpVersion::V2c,
            community: b"public".to_vec(),
            pdu: Pdu {
                kind: PduKind::SnmpV2Trap,
                request_id: 42,
                error_status: 0,
                error_index: 0,
                varbinds: vec![
                    VarBind::new(oid(&SYS_UPTIME_INSTANCE_OID), SnmpValue::TimeTicks(123)),
                    VarBind::new(
                        oid(&SNMP_TRAP_OID_INSTANCE_OID),
                        SnmpValue::ObjectIdentifier(oid(&[1, 3, 6, 1, 6, 3, 1, 1, 5, 3])),
                    ),
                    VarBind::new(
                        oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 7]),
                        SnmpValue::Integer(7),
                    ),
                ],
                v1_trap: None,
            },
        }
    }

    #[test]
    fn to_dict_matches_reference_without_bundle() {
        let event = notification_event_from_message(
            &trap_message(),
            Some("10.0.0.1:12345".parse().unwrap()),
            None,
        )
        .unwrap();
        let d = event.to_dict();
        assert_eq!(d["request_id"], 42);
        assert_eq!(d["community"], "public");
        assert_eq!(d["source_host"], "10.0.0.1");
        assert_eq!(d["source_port"], 12345);
        assert_eq!(d["pdu_type"], "snmpv2-trap");
        assert_eq!(d["notification_oid"], "1.3.6.1.6.3.1.1.5.3");
        assert_eq!(d["notification_name"], serde_json::Value::Null);
        assert_eq!(d["notification_description"], serde_json::Value::Null);
        assert_eq!(d["uptime"], 123);
        assert_eq!(d["varbinds"].as_array().unwrap().len(), 3);
        assert_eq!(d["member_bindings"].as_array().unwrap().len(), 0);
        // v1/v3-only keys are absent.
        assert!(d.get("enterprise").is_none());
        assert!(d.get("snmp_version").is_none());
        // JSON round-trips without error.
        let _ = serde_json::to_string(&event).unwrap();
    }

    #[test]
    fn to_dict_without_source_address() {
        let message = SnmpMessage {
            version: SnmpVersion::V2c,
            community: b"mgmt".to_vec(),
            pdu: Pdu {
                kind: PduKind::SnmpV2Trap,
                request_id: 1,
                error_status: 0,
                error_index: 0,
                varbinds: Vec::new(),
                v1_trap: None,
            },
        };
        let event = notification_event_from_message(&message, None, None).unwrap();
        let d = event.to_dict();
        assert_eq!(d["source_host"], serde_json::Value::Null);
        assert_eq!(d["source_port"], serde_json::Value::Null);
        assert_eq!(d["varbinds"].as_array().unwrap().len(), 0);
        assert_eq!(d["member_bindings"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn to_dict_varbind_fields_without_bundle() {
        let event = notification_event_from_message(&trap_message(), None, None).unwrap();
        let d = event.to_dict();
        let uptime_vb = &d["varbinds"][0];
        assert_eq!(uptime_vb["oid"], "1.3.6.1.2.1.1.3.0");
        assert_eq!(uptime_vb["value_type"], "timeticks");
        assert_eq!(uptime_vb["value"], "123");
        assert_eq!(uptime_vb["display_name"], serde_json::Value::Null);
    }

    #[test]
    fn v1_trap_event_carries_trap_metadata() {
        let message = SnmpMessage {
            version: SnmpVersion::V1,
            community: b"public".to_vec(),
            pdu: Pdu {
                kind: PduKind::Trap,
                request_id: 0,
                error_status: 0,
                error_index: 0,
                varbinds: vec![VarBind::new(
                    oid(&SYS_UPTIME_INSTANCE_OID),
                    SnmpValue::TimeTicks(10),
                )],
                v1_trap: Some(V1TrapFields {
                    enterprise: oid(&[1, 3, 6, 1, 4, 1, 999]),
                    agent_addr: Ipv4Addr::new(192, 0, 2, 1),
                    generic_trap: 6,
                    specific_trap: 1,
                    timestamp: 10,
                }),
            },
        };
        let event = notification_event_from_message(&message, None, None).unwrap();
        assert_eq!(event.pdu_type, "trap");
        let d = event.to_dict();
        assert_eq!(d["enterprise"], "1.3.6.1.4.1.999");
        assert_eq!(d["agent_addr"], "192.0.2.1");
        assert_eq!(d["generic_trap"], 6);
        assert_eq!(d["specific_trap"], 1);
        assert_eq!(d["timestamp"], 10);
        assert!(d.get("snmp_version").is_none());
    }

    #[test]
    fn non_notification_pdu_is_rejected() {
        let message = SnmpMessage {
            version: SnmpVersion::V2c,
            community: b"public".to_vec(),
            pdu: Pdu {
                kind: PduKind::GetRequest,
                request_id: 8,
                error_status: 0,
                error_index: 0,
                varbinds: Vec::new(),
                v1_trap: None,
            },
        };
        let err = notification_event_from_message(&message, None, None).unwrap_err();
        assert!(
            err.message.contains("Unsupported notification PDU type"),
            "{err}"
        );
    }

    #[test]
    fn decode_notification_rejects_v2c_message_with_v3_user() {
        // A v2c message must fail the v3 path with a "version 3" protocol error.
        let message = trap_message();
        let encoded = crate::codec::message::encode_message(&message).unwrap();
        let user = UsmUser::new(
            "notify".to_string(),
            AuthProtocol::None_,
            AuthKey::Passphrase(Vec::new()),
            PrivProtocol::None_,
            PrivKey::Passphrase(Vec::new()),
        )
        .unwrap();
        let err = decode_notification(&encoded, None, Some(&user), None).unwrap_err();
        assert!(err.to_string().contains("version 3"), "{err}");
    }

    #[test]
    fn decode_notification_v3_wrong_user_raises_protocol_error() {
        let user = UsmUser::new(
            "notify".to_string(),
            AuthProtocol::None_,
            AuthKey::Passphrase(Vec::new()),
            PrivProtocol::None_,
            PrivKey::Passphrase(Vec::new()),
        )
        .unwrap();
        let other = UsmUser::new(
            "someone-else".to_string(),
            AuthProtocol::None_,
            AuthKey::Passphrase(Vec::new()),
            PrivProtocol::None_,
            PrivKey::Passphrase(Vec::new()),
        )
        .unwrap();
        let model = UsmModel::new(
            other.clone(),
            b"alerts".to_vec(),
            Some(crate::security::usm::UsmLocalEngine {
                engine_id: [vec![0x80, 0x00, 0x01, 0x02, 0x03], vec![0x44; 12]].concat(),
                engine_boots: 9,
                engine_time: 321,
            }),
            std::sync::Arc::new(SystemClock),
            std::sync::Arc::new(SystemRng),
        );
        let raw = model
            .wrap_pdu(&Pdu {
                kind: PduKind::SnmpV2Trap,
                request_id: 77,
                error_status: 0,
                error_index: 0,
                varbinds: Vec::new(),
                v1_trap: None,
            })
            .unwrap();
        let err = decode_notification(&raw, None, Some(&user), None).unwrap_err();
        assert!(err.to_string().contains("configured user"), "{err}");
    }
}
