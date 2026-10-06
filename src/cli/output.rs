//! Text/JSON renderers (← cli/output.py)
//!
//! stdout shapes are the pinned CLI contract: every string here matches the
//! reference's output.py byte-for-byte (docs/cli.md). The JSON
//! payloads reproduce `_response_payload`, `_varbind_payload`, and
//! `_notification_payload`; key insertion order is irrelevant (JSON objects
//! compare by key), but key presence/absence and values are exact.

use serde_json::{Map, Value, json};

use crate::notify::event::{NotificationEvent, NotificationMemberBinding};
use crate::types::varbind::{Response, VarBind};

/// Renders a translated OID or symbol (output.py:render_translation).
#[must_use]
pub fn render_translation(result: &str) -> String {
    result.to_string()
}

/// Renders an SNMP response for CLI output (output.py:render_response).
#[must_use]
pub fn render_response(response: &Response, json_output: bool, numeric: bool) -> String {
    if json_output {
        return serde_json::to_string_pretty(&response_payload(response))
            .expect("response payload serializes");
    }
    let mut lines: Vec<String> = Vec::new();
    if response.error_status != crate::types::varbind::ErrorStatus::NoError {
        lines.push(format!(
            "error_status={} error_index={}",
            response.error_status.label(),
            response.error_index
        ));
    }
    lines.extend(
        response
            .varbinds
            .iter()
            .map(|varbind| render_varbind_text(varbind, numeric)),
    );
    lines.join("\n")
}

/// Renders walked varbinds for CLI output (output.py:render_walk).
#[must_use]
pub fn render_walk(varbinds: &[VarBind], json_output: bool, numeric: bool) -> String {
    if json_output {
        let payload = json!({
            "varbinds": varbinds.iter().map(varbind_payload).collect::<Vec<_>>(),
        });
        return serde_json::to_string_pretty(&payload).expect("walk payload serializes");
    }
    varbinds
        .iter()
        .map(|varbind| render_varbind_text(varbind, numeric))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Renders a request identifier for trap-style CLI commands
/// (output.py:render_request_id).
#[must_use]
pub fn render_request_id(request_id: u32, json_output: bool) -> String {
    if json_output {
        return serde_json::to_string_pretty(&json!({ "request_id": request_id }))
            .expect("request id payload serializes");
    }
    format!("request_id={request_id}")
}

/// Renders the timestamp returned by an SNMPv1 trap send
/// (output.py:render_v1_trap_timestamp).
#[must_use]
pub fn render_v1_trap_timestamp(timestamp: u32, json_output: bool) -> String {
    if json_output {
        return serde_json::to_string_pretty(&json!({ "timestamp": timestamp }))
            .expect("timestamp payload serializes");
    }
    format!("timestamp={timestamp}")
}

/// Renders a decoded notification event (output.py:render_notification_event).
#[must_use]
pub fn render_notification_event(
    event: &NotificationEvent,
    json_output: bool,
    numeric: bool,
    compact: bool,
) -> String {
    if json_output {
        let payload = notification_payload(event);
        return if compact {
            serde_json::to_string(&payload).expect("notification payload serializes")
        } else {
            serde_json::to_string_pretty(&payload).expect("notification payload serializes")
        };
    }

    let mut header: Vec<String> = vec![
        format!("type={}", event.pdu_type),
        format!("request_id={}", event.request_id),
    ];
    if let Some(community) = &event.community {
        header.push(format!("community={}", community_to_string(community)));
    } else if let Some(username) = &event.username {
        header.push(format!("user={username}"));
        if let Some(level) = &event.security_level {
            header.push(format!("level={level}"));
        }
    }
    if let (Some(host), Some(port)) = (event.source_host(), event.source_port()) {
        header.push(format!("source={host}:{port}"));
    }

    let mut lines = vec![header.join(" ")];
    if let Some(v1_line) = v1_trap_detail_line(event) {
        lines.push(v1_line);
    }
    if let Some(detail_line) = notification_detail_line(event, numeric) {
        lines.push(detail_line);
    }
    if let Some(description) = &event.notification_description {
        lines.push(description.clone());
    }
    lines.extend(
        event
            .varbinds
            .iter()
            .map(|varbind| render_varbind_text(varbind, numeric)),
    );
    lines.join("\n")
}

/// One `NAME = VALUE` line (output.py:_render_varbind_text).
fn render_varbind_text(varbind: &VarBind, numeric: bool) -> String {
    let name = if numeric || varbind.display_name.is_none() {
        varbind.oid_str()
    } else {
        varbind.display_name.clone().expect("checked above")
    };
    let value = varbind
        .display_value
        .clone()
        .unwrap_or_else(|| varbind.value.to_string());
    format!("{name} = {value}")
}

/// The response JSON payload (output.py:_response_payload).
fn response_payload(response: &Response) -> Value {
    json!({
        "request_id": response.request_id,
        "error_status": response.error_status.label(),
        "error_status_code": response.error_status.as_raw(),
        "error_index": response.error_index,
        "varbinds": response.varbinds.iter().map(varbind_payload).collect::<Vec<_>>(),
    })
}

/// One varbind JSON payload (output.py:_varbind_payload).
fn varbind_payload(varbind: &VarBind) -> Value {
    let mut payload: Map<String, Value> = Map::new();
    payload.insert("oid".to_string(), json!(varbind.oid_str()));
    payload.insert("value_type".to_string(), json!(varbind.value_type()));
    payload.insert(
        "display_value".to_string(),
        json!(
            varbind
                .display_value
                .clone()
                .unwrap_or_else(|| varbind.value.to_string())
        ),
    );
    if let Some(display_name) = &varbind.display_name {
        payload.insert("display_name".to_string(), json!(display_name));
    }
    if let Some(enum_label) = &varbind.enum_label {
        payload.insert("enum_label".to_string(), json!(enum_label));
    }
    if let Some(units) = &varbind.units {
        payload.insert("units".to_string(), json!(units));
    }
    Value::Object(payload)
}

/// The notification event JSON payload (output.py:_notification_payload).
fn notification_payload(event: &NotificationEvent) -> Value {
    let mut payload: Map<String, Value> = Map::new();
    payload.insert("request_id".to_string(), json!(event.request_id));
    payload.insert(
        "community".to_string(),
        event
            .community
            .as_deref()
            .map(community_to_string)
            .map_or(Value::Null, Value::String),
    );
    payload.insert("pdu_type".to_string(), json!(event.pdu_type));
    payload.insert(
        "varbinds".to_string(),
        json!(
            event
                .varbinds
                .iter()
                .map(varbind_payload)
                .collect::<Vec<_>>()
        ),
    );
    payload.insert(
        "member_bindings".to_string(),
        json!(
            event
                .member_bindings
                .iter()
                .map(member_binding_payload)
                .collect::<Vec<_>>()
        ),
    );
    if let Some(source_address) = event.source_address {
        payload.insert(
            "source_address".to_string(),
            json!({ "host": source_address.ip().to_string(), "port": source_address.port() }),
        );
    }
    if let Some(notification_oid) = &event.notification_oid {
        payload.insert(
            "notification_oid".to_string(),
            json!(notification_oid.display()),
        );
    }
    if let Some(notification_name) = &event.notification_name {
        payload.insert("notification_name".to_string(), json!(notification_name));
    }
    if let Some(notification_description) = &event.notification_description {
        payload.insert(
            "notification_description".to_string(),
            json!(notification_description),
        );
    }
    if let Some(uptime) = event.uptime {
        payload.insert("uptime".to_string(), json!(uptime));
    }
    if let Some(snmp_version) = &event.snmp_version {
        payload.insert("snmp_version".to_string(), json!(snmp_version));
    }
    if let Some(username) = &event.username {
        payload.insert("username".to_string(), json!(username));
    }
    if let Some(security_level) = &event.security_level {
        payload.insert("security_level".to_string(), json!(security_level));
    }
    if let Some(context_engine_id) = &event.context_engine_id {
        payload.insert(
            "context_engine_id".to_string(),
            json!(hex(context_engine_id)),
        );
    }
    if let Some(context_name) = &event.context_name {
        payload.insert("context_name".to_string(), json!(hex(context_name)));
    }
    if let Some(authoritative_engine_id) = &event.authoritative_engine_id {
        payload.insert(
            "authoritative_engine_id".to_string(),
            json!(hex(authoritative_engine_id)),
        );
    }
    if let Some(authoritative_engine_boots) = event.authoritative_engine_boots {
        payload.insert(
            "authoritative_engine_boots".to_string(),
            json!(authoritative_engine_boots),
        );
    }
    if let Some(authoritative_engine_time) = event.authoritative_engine_time {
        payload.insert(
            "authoritative_engine_time".to_string(),
            json!(authoritative_engine_time),
        );
    }
    if let Some(enterprise) = &event.enterprise {
        payload.insert("enterprise".to_string(), json!(enterprise.display()));
    }
    if let Some(agent_addr) = &event.agent_addr {
        payload.insert("agent_addr".to_string(), json!(agent_addr));
    }
    if let Some(generic_trap) = event.generic_trap {
        payload.insert("generic_trap".to_string(), json!(generic_trap));
    }
    if let Some(specific_trap) = event.specific_trap {
        payload.insert("specific_trap".to_string(), json!(specific_trap));
    }
    if let Some(timestamp) = event.timestamp {
        payload.insert("timestamp".to_string(), json!(timestamp));
    }
    Value::Object(payload)
}

/// One member-binding JSON payload (output.py:_member_binding_payload).
fn member_binding_payload(binding: &NotificationMemberBinding) -> Value {
    json!({
        "member": binding.symbolic(),
        "varbind": binding.varbind.as_ref().map(varbind_payload),
    })
}

/// The v1 Trap-PDU detail line, or `None` when no v1 field is present
/// (output.py:_v1_trap_detail_line).
fn v1_trap_detail_line(event: &NotificationEvent) -> Option<String> {
    if event.enterprise.is_none()
        && event.agent_addr.is_none()
        && event.generic_trap.is_none()
        && event.specific_trap.is_none()
        && event.timestamp.is_none()
    {
        return None;
    }
    let mut details: Vec<String> = Vec::new();
    if let Some(enterprise) = &event.enterprise {
        details.push(format!("enterprise={}", enterprise.display()));
    }
    if let Some(agent_addr) = &event.agent_addr {
        details.push(format!("agent-addr={agent_addr}"));
    }
    if let Some(generic_trap) = event.generic_trap {
        details.push(format!("generic-trap={generic_trap}"));
    }
    if let Some(specific_trap) = event.specific_trap {
        details.push(format!("specific-trap={specific_trap}"));
    }
    if let Some(timestamp) = event.timestamp {
        details.push(format!("timestamp={timestamp}"));
    }
    Some(details.join(" "))
}

/// The `notification=… uptime=…` detail line, or `None` when neither is
/// present (output.py:_notification_detail_line).
fn notification_detail_line(event: &NotificationEvent, numeric: bool) -> Option<String> {
    let mut details: Vec<String> = Vec::new();
    if let Some(label) = notification_label(event, numeric) {
        details.push(format!("notification={label}"));
    }
    if let Some(uptime) = event.uptime {
        details.push(format!("uptime={uptime}"));
    }
    if details.is_empty() {
        return None;
    }
    Some(details.join(" "))
}

/// The notification label (output.py:_notification_label).
fn notification_label(event: &NotificationEvent, numeric: bool) -> Option<String> {
    if numeric {
        return event
            .notification_oid
            .as_ref()
            .map(crate::types::oid::Oid::display);
    }
    if let Some(notification_name) = &event.notification_name {
        return Some(notification_name.clone());
    }
    event
        .notification_oid
        .as_ref()
        .map(crate::types::oid::Oid::display)
}

/// Lowercase hex, matching the reference's `.hex()` byte-field encoding.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The reference's community decoding (message.py:95–97): UTF-8 first, then
/// latin-1 (each byte becomes the codepoint with that value).
fn community_to_string(community: &[u8]) -> String {
    match std::str::from_utf8(community) {
        Ok(text) => text.to_string(),
        Err(_) => community.iter().map(|&byte| char::from(byte)).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::oid::Oid;
    use crate::types::value::SnmpValue;
    use crate::types::varbind::ErrorStatus;

    fn oid(arcs: &[u32]) -> Oid {
        Oid::from_arcs(arcs).unwrap()
    }

    fn varbind(
        arcs: &[u32],
        value: SnmpValue,
        display_name: Option<&str>,
        display_value: Option<&str>,
        enum_label: Option<&str>,
        units: Option<&str>,
    ) -> VarBind {
        let mut vb = VarBind::new(oid(arcs), value);
        vb.display_name = display_name.map(str::to_string);
        vb.display_value = display_value.map(str::to_string);
        vb.enum_label = enum_label.map(str::to_string);
        vb.units = units.map(str::to_string);
        vb
    }

    #[test]
    fn render_response_includes_error_status_line() {
        let response = Response {
            request_id: 99,
            error_status: ErrorStatus::GenErr,
            error_index: 2,
            varbinds: vec![varbind(
                &[1, 3, 6, 1, 2, 1, 1, 3, 0],
                SnmpValue::Integer(7),
                Some("SNMPv2-MIB::sysUpTime.0"),
                None,
                None,
                None,
            )],
        };
        let rendered = render_response(&response, false, false);
        assert_eq!(
            rendered.split('\n').collect::<Vec<_>>(),
            [
                "error_status=gen_err error_index=2",
                "SNMPv2-MIB::sysUpTime.0 = 7"
            ]
        );
    }

    #[test]
    fn render_walk_json_output() {
        let rendered = render_walk(
            &[varbind(
                &[1, 3, 6, 1, 2, 1, 2, 2, 1, 1],
                SnmpValue::Integer(7),
                Some("IF-MIB::ifIndex.1"),
                Some("7"),
                None,
                None,
            )],
            true,
            false,
        );
        let payload: Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(
            payload,
            json!({
                "varbinds": [{
                    "oid": "1.3.6.1.2.1.2.2.1.1",
                    "value_type": "integer",
                    "display_name": "IF-MIB::ifIndex.1",
                    "display_value": "7",
                }]
            })
        );
    }

    #[test]
    fn render_walk_json_output_includes_enum_label_and_units_when_present() {
        let rendered = render_walk(
            &[
                varbind(
                    &[1, 3, 6, 1, 2, 1, 2, 2, 1, 8, 1],
                    SnmpValue::Integer(1),
                    Some("IF-MIB::ifOperStatus.1"),
                    Some("up(1)"),
                    Some("up"),
                    None,
                ),
                varbind(
                    &[1, 3, 6, 1, 2, 1, 2, 2, 1, 5, 1],
                    SnmpValue::Gauge32(1000),
                    Some("IF-MIB::ifSpeed.1"),
                    Some("1000"),
                    None,
                    Some("bits/second"),
                ),
            ],
            true,
            false,
        );
        let payload: Value = serde_json::from_str(&rendered).unwrap();
        let varbinds = payload["varbinds"].as_array().unwrap();
        assert_eq!(varbinds[0]["enum_label"], "up");
        assert_eq!(varbinds[1]["units"], "bits/second");
        assert!(varbinds[1].get("enum_label").is_none());
        assert!(varbinds[0].get("units").is_none());
    }

    #[test]
    fn render_response_text_output_renders_enum_display_value() {
        let response = Response {
            request_id: 3,
            error_status: ErrorStatus::NoError,
            error_index: 0,
            varbinds: vec![varbind(
                &[1, 3, 6, 1, 2, 1, 2, 2, 1, 8, 1],
                SnmpValue::Integer(1),
                Some("IF-MIB::ifOperStatus.1"),
                Some("up(1)"),
                Some("up"),
                None,
            )],
        };
        let rendered = render_response(&response, false, false);
        assert_eq!(rendered, "IF-MIB::ifOperStatus.1 = up(1)");
    }

    #[test]
    fn render_notification_event_json_includes_enum_label_and_units() {
        let vb = varbind(
            &[1, 3, 6, 1, 4, 1, 99999, 1, 0],
            SnmpValue::Integer(1),
            Some("APP-MIB::status.0"),
            Some("up(1)"),
            Some("up"),
            None,
        );
        let mut event = base_event();
        event.varbinds = vec![vb.clone()];
        event.notification_oid = Some(oid(&[1, 3, 6, 1, 4, 1, 99999, 10]));
        event.notification_name = Some("APP-MIB::statusNotice".to_string());
        event.member_bindings = vec![NotificationMemberBinding {
            symbolic: "APP-MIB::status".to_string(),
            varbind: Some(vb),
        }];
        let rendered = render_notification_event(&event, true, false, false);
        let payload: Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(payload["varbinds"][0]["enum_label"], "up");
        assert_eq!(payload["member_bindings"][0]["varbind"]["enum_label"], "up");
    }

    #[test]
    fn render_request_id_json_output() {
        assert_eq!(
            serde_json::from_str::<Value>(&render_request_id(17, true)).unwrap(),
            json!({ "request_id": 17 })
        );
    }

    #[test]
    fn render_v1_trap_timestamp_text_and_json() {
        assert_eq!(render_v1_trap_timestamp(654321, false), "timestamp=654321");
        assert_eq!(
            serde_json::from_str::<Value>(&render_v1_trap_timestamp(654321, true)).unwrap(),
            json!({ "timestamp": 654321 })
        );
    }

    #[test]
    fn render_notification_event_text_and_json() {
        let vb = varbind(
            &[1, 3, 6, 1, 4, 1, 99999, 1, 0],
            SnmpValue::Integer(7),
            Some("APP-MIB::status.0"),
            Some("7"),
            None,
            None,
        );
        let mut event = base_event();
        event.request_id = 9;
        event.varbinds = vec![vb.clone()];
        event.notification_oid = Some(oid(&[1, 3, 6, 1, 4, 1, 99999, 10]));
        event.notification_name = Some("APP-MIB::statusNotice".to_string());
        event.notification_description = Some("Status changed.".to_string());
        event.uptime = Some(55);
        event.member_bindings = vec![NotificationMemberBinding {
            symbolic: "APP-MIB::status".to_string(),
            varbind: Some(vb),
        }];

        let rendered_text = render_notification_event(&event, false, false, false);
        assert_eq!(
            rendered_text.split('\n').collect::<Vec<_>>(),
            [
                "type=snmpv2-trap request_id=9 community=public source=127.0.0.1:40162",
                "notification=APP-MIB::statusNotice uptime=55",
                "Status changed.",
                "APP-MIB::status.0 = 7",
            ]
        );

        let rendered_json = render_notification_event(&event, true, false, false);
        let payload: Value = serde_json::from_str(&rendered_json).unwrap();
        assert_eq!(payload["request_id"], 9);
        assert_eq!(payload["community"], "public");
        assert_eq!(payload["pdu_type"], "snmpv2-trap");
        assert_eq!(
            payload["source_address"],
            json!({ "host": "127.0.0.1", "port": 40162 })
        );
        assert_eq!(payload["notification_oid"], "1.3.6.1.4.1.99999.10");
        assert_eq!(payload["notification_name"], "APP-MIB::statusNotice");
        assert_eq!(payload["notification_description"], "Status changed.");
        assert_eq!(payload["uptime"], 55);
        assert_eq!(
            payload["member_bindings"],
            json!([{ "member": "APP-MIB::status", "varbind": {
                "oid": "1.3.6.1.4.1.99999.1.0",
                "value_type": "integer",
                "display_name": "APP-MIB::status.0",
                "display_value": "7",
            } }])
        );
        assert_eq!(payload["varbinds"][0]["display_name"], "APP-MIB::status.0");
    }

    #[test]
    fn render_notification_event_v1_text_and_json() {
        let mut event = base_event();
        event.request_id = 0;
        event.source_address = Some("192.0.2.10:40162".parse().unwrap());
        event.pdu_type = "trap".to_string();
        event.varbinds = vec![varbind(
            &[1, 3, 6, 1, 4, 1, 999, 0, 1],
            SnmpValue::Integer(7),
            Some("APP-MIB::alarm.0"),
            Some("7"),
            None,
            None,
        )];
        event.uptime = Some(654321);
        event.enterprise = Some(oid(&[1, 3, 6, 1, 4, 1, 999]));
        event.agent_addr = Some("192.0.2.10".to_string());
        event.generic_trap = Some(6);
        event.specific_trap = Some(0);
        event.timestamp = Some(654321);

        let rendered_text = render_notification_event(&event, false, false, false);
        assert_eq!(
            rendered_text.split('\n').collect::<Vec<_>>(),
            [
                "type=trap request_id=0 community=public source=192.0.2.10:40162",
                "enterprise=1.3.6.1.4.1.999 agent-addr=192.0.2.10 generic-trap=6 specific-trap=0 timestamp=654321",
                "uptime=654321",
                "APP-MIB::alarm.0 = 7",
            ]
        );

        let rendered_json = render_notification_event(&event, true, false, false);
        let payload: Value = serde_json::from_str(&rendered_json).unwrap();
        assert_eq!(payload["enterprise"], "1.3.6.1.4.1.999");
        assert_eq!(payload["agent_addr"], "192.0.2.10");
        assert_eq!(payload["generic_trap"], 6);
        assert_eq!(payload["specific_trap"], 0);
        assert_eq!(payload["timestamp"], 654321);
        assert_eq!(payload["member_bindings"], json!([]));
    }

    #[test]
    fn render_notification_event_omits_v1_fields_when_absent() {
        let mut event = base_event();
        event.source_address = None;
        let rendered_text = render_notification_event(&event, false, false, false);
        assert_eq!(
            rendered_text,
            "type=snmpv2-trap request_id=8 community=public"
        );
        let payload: Value =
            serde_json::from_str(&render_notification_event(&event, true, false, false)).unwrap();
        for key in [
            "enterprise",
            "agent_addr",
            "generic_trap",
            "specific_trap",
            "timestamp",
        ] {
            assert!(payload.get(key).is_none(), "{key} must be absent");
        }
    }

    #[test]
    fn render_notification_event_handles_compact_json_and_fallback_labels() {
        let mut event = base_event();
        event.request_id = 4;
        event.source_address = None;
        event.pdu_type = "inform-request".to_string();
        event.notification_oid = Some(oid(&[1, 3, 6, 1, 4, 1, 99999, 10]));
        event.member_bindings = vec![NotificationMemberBinding {
            symbolic: "APP-MIB::status".to_string(),
            varbind: None,
        }];
        let rendered_text = render_notification_event(&event, false, false, false);
        assert_eq!(
            rendered_text.split('\n').collect::<Vec<_>>(),
            [
                "type=inform-request request_id=4 community=public",
                "notification=1.3.6.1.4.1.99999.10",
            ]
        );
        let rendered_compact = render_notification_event(&event, true, false, true);
        assert!(
            !rendered_compact.contains('\n'),
            "compact JSON is single-line"
        );
        let payload: Value = serde_json::from_str(&rendered_compact).unwrap();
        assert_eq!(
            payload["member_bindings"],
            json!([{ "member": "APP-MIB::status", "varbind": null }])
        );
    }

    #[test]
    fn render_notification_event_omits_detail_line_when_no_notification_or_uptime() {
        let mut event = base_event();
        event.source_address = None;
        assert_eq!(
            render_notification_event(&event, false, true, false),
            "type=snmpv2-trap request_id=8 community=public"
        );
        assert_eq!(
            render_notification_event(&event, false, false, false),
            "type=snmpv2-trap request_id=8 community=public"
        );
    }

    #[test]
    fn render_notification_event_v3_text_and_json() {
        let mut event = base_event();
        event.community = None;
        event.pdu_type = "inform-request".to_string();
        event.snmp_version = Some("3".to_string());
        event.username = Some("alice".to_string());
        event.security_level = Some("authPriv".to_string());
        event.context_engine_id = Some(vec![0x80, 0x00, 0x01, 0x02, 0x03]);
        event.context_name = Some(b"alerts".to_vec());
        event.authoritative_engine_id = Some(vec![0x80, 0x00, 0xaa, 0xbb, 0xcc]);
        event.authoritative_engine_boots = Some(9);
        event.authoritative_engine_time = Some(123);

        let rendered_text = render_notification_event(&event, false, false, false);
        assert_eq!(
            rendered_text,
            "type=inform-request request_id=8 user=alice level=authPriv source=127.0.0.1:40162"
        );
        let payload: Value =
            serde_json::from_str(&render_notification_event(&event, true, false, false)).unwrap();
        assert_eq!(payload["community"], Value::Null);
        assert_eq!(payload["snmp_version"], "3");
        assert_eq!(payload["username"], "alice");
        assert_eq!(payload["security_level"], "authPriv");
        assert_eq!(payload["context_engine_id"], "8000010203");
        assert_eq!(payload["context_name"], "616c65727473");
        assert_eq!(payload["authoritative_engine_id"], "8000aabbcc");
        assert_eq!(payload["authoritative_engine_boots"], 9);
        assert_eq!(payload["authoritative_engine_time"], 123);
    }

    #[test]
    fn varbind_payload_prefers_display_value_and_falls_back_to_value() {
        let enriched = varbind(
            &[1, 3, 6, 1, 2, 1, 1, 1, 0],
            SnmpValue::Integer(7),
            None,
            Some("custom"),
            None,
            None,
        );
        assert_eq!(varbind_payload(&enriched)["display_value"], "custom");
        let raw = VarBind::new(oid(&[1, 3, 6, 1, 2, 1, 1, 1, 0]), SnmpValue::Integer(7));
        assert_eq!(varbind_payload(&raw)["display_value"], "7");
    }

    /// The shared event fixture (test_cli_output.py's base event).
    fn base_event() -> NotificationEvent {
        NotificationEvent {
            request_id: 8,
            community: Some(b"public".to_vec()),
            source_address: Some("127.0.0.1:40162".parse().unwrap()),
            pdu_type: "snmpv2-trap".to_string(),
            varbinds: Vec::new(),
            notification_oid: None,
            notification_name: None,
            notification_description: None,
            uptime: None,
            member_bindings: Vec::new(),
            snmp_version: None,
            username: None,
            security_level: None,
            context_engine_id: None,
            context_name: None,
            authoritative_engine_id: None,
            authoritative_engine_boots: None,
            authoritative_engine_time: None,
            enterprise: None,
            agent_addr: None,
            generic_trap: None,
            specific_trap: None,
            timestamp: None,
        }
    }
}
