//! Enum/BITS/units enrichment (← mib/render.py)
//!
//! `enrich_varbinds` attaches the symbolic name and value-rendering metadata
//! to each varbind when a bundle is available: enum labels render as
//! `up(1)`, BITS octet strings as `red(0) green(1)`, OBJECT IDENTIFIER values
//! translate to symbolic form, and UNITS clauses are attached for consumers.
//! Without a bundle only the raw display string is populated (matching the
//! reference's `enrich_varbinds(None, …)`).

use std::collections::BTreeMap;

use crate::mib::MibBundle;
use crate::types::value::SnmpValue;
use crate::types::varbind::{OidMatch, VarBind};

/// Attaches symbolic names and value metadata when a bundle is available
/// (render.py:19–60).
pub fn enrich_varbinds(bundle: Option<&MibBundle>, varbinds: Vec<VarBind>) -> Vec<VarBind> {
    if bundle.is_none() {
        return varbinds
            .into_iter()
            .map(|varbind| VarBind {
                display_value: Some(varbind.value.to_string()),
                ..varbind
            })
            .collect();
    }
    let bundle = bundle.expect("checked above");

    let mut enriched = Vec::with_capacity(varbinds.len());
    for varbind in varbinds {
        let match_ = bundle.lookup(&varbind.oid).ok();
        let metadata = match_
            .as_ref()
            .and_then(|_| bundle.lookup_metadata(&varbind.oid));
        let enum_label = match (&varbind.value, &match_) {
            (SnmpValue::Integer(value), Some(match_)) => resolve_enum_label(bundle, match_, *value),
            _ => None,
        };
        let display_name = match_
            .as_ref()
            .map(|m| bundle.display_symbolic_from_match(m));
        let display_value = render_value(bundle, &varbind, match_.as_ref(), enum_label.as_deref());
        enriched.push(VarBind {
            matched: match_,
            display_name,
            display_value: Some(display_value),
            enum_label,
            units: metadata.and_then(|m| m.units.clone()),
            ..varbind
        });
    }
    enriched
}

/// The rendered value text for a varbind (render.py:69–90).
fn render_value(
    bundle: &MibBundle,
    varbind: &VarBind,
    match_: Option<&OidMatch>,
    enum_label: Option<&str>,
) -> String {
    match &varbind.value {
        SnmpValue::ObjectIdentifier(oid) => bundle
            .translate(&oid.display())
            .unwrap_or_else(|_| varbind.value.to_string()),
        SnmpValue::Integer(value) if enum_label.is_some() => {
            format!("{}({value})", enum_label.expect("checked above"))
        }
        SnmpValue::OctetString(bytes) if match_.is_some() => {
            let match_ = match_.expect("checked above");
            let bits = resolve_bits_labels(bundle, match_, bytes);
            if let Some(bits) = bits.filter(|bits| !bits.is_empty()) {
                return bits
                    .iter()
                    .map(|(label, bit)| format!("{label}({bit})"))
                    .collect::<Vec<_>>()
                    .join(" ");
            }
            varbind.value.to_string()
        }
        _ => varbind.value.to_string(),
    }
}

/// Resolves the enum label for an INTEGER value (render.py:93–113): the node's
/// inline `enums` map first, then the node's enum constraints, then the
/// imported textual convention's enum constraints.
fn resolve_enum_label(bundle: &MibBundle, match_: &OidMatch, value: i64) -> Option<String> {
    let node = resolve_node(bundle, match_)?;

    if let Some(label) = node
        .enums
        .as_ref()
        .and_then(|enums| enum_label_from_map(enums, value))
    {
        return Some(label);
    }

    if let Some(label) = enum_label_from_constraints(node.constraints.as_ref(), value) {
        return Some(label);
    }

    let syntax = node.syntax.as_ref()?;
    let type_record = bundle.resolve_type(&match_.module, syntax)?;
    enum_label_from_constraints(type_record.constraints.as_ref(), value)
}

/// Resolves `(label, bit)` pairs for set bits when `match_` owns a BITS
/// object (render.py:129–156). BITS octet strings encode bit 0 as the most
/// significant bit of the first byte. `None` for non-BITS objects.
fn resolve_bits_labels(
    bundle: &MibBundle,
    match_: &OidMatch,
    value: &[u8],
) -> Option<Vec<(String, u32)>> {
    let node = resolve_node(bundle, match_)?;
    let enum_map = bits_enum_map(bundle, match_, node)?;
    if enum_map.is_empty() {
        return None;
    }

    let mut labels = Vec::new();
    for (byte_index, byte) in value.iter().enumerate() {
        for bit in 0..8 {
            if byte & (1 << (7 - bit)) != 0 {
                let bit_number = (byte_index * 8 + bit) as i64;
                if let Some(label) = enum_label_from_map(&enum_map, bit_number) {
                    labels.push((label, (byte_index * 8 + bit) as u32));
                }
            }
        }
    }
    Some(labels)
}

/// Resolves the label→bit map for a BITS object (render.py:159–174): the
/// node's inline `enums` when it is a BITS node, the node's bits constraints,
/// or the imported textual convention's bits constraints.
fn bits_enum_map(
    bundle: &MibBundle,
    match_: &OidMatch,
    node: &crate::mib::model::MibNode,
) -> Option<BTreeMap<String, i64>> {
    if node.enums.is_some() && is_bits_node(bundle, match_, node) {
        return node.enums.clone();
    }
    if constraint_kind(node.constraints.as_ref()) == Some("bits") {
        return constraint_enum_map(node.constraints.as_ref());
    }
    let syntax = node.syntax.as_ref()?;
    let type_record = bundle.resolve_type(&match_.module, syntax)?;
    if constraint_kind(type_record.constraints.as_ref()) == Some("bits") {
        return constraint_enum_map(type_record.constraints.as_ref());
    }
    None
}

/// Whether `node` is a BITS object (render.py:177–185): inline BITS syntax or
/// bits constraints, or a textual convention whose base type is BITS.
fn is_bits_node(bundle: &MibBundle, match_: &OidMatch, node: &crate::mib::model::MibNode) -> bool {
    if node.syntax.as_deref() == Some("BITS")
        || constraint_kind(node.constraints.as_ref()) == Some("bits")
    {
        return true;
    }
    let Some(syntax) = node.syntax.as_ref() else {
        return false;
    };
    let Some(type_record) = bundle.resolve_type(&match_.module, syntax) else {
        return false;
    };
    type_record.base_type.as_deref() == Some("BITS")
        || constraint_kind(type_record.constraints.as_ref()) == Some("bits")
}

/// The `kind` field of a constraint object (render.py:188–192).
fn constraint_kind(constraints: Option<&serde_json::Value>) -> Option<&str> {
    constraints?.as_object()?.get("kind")?.as_str()
}

/// Builds a label→number map from enum/bits constraint data (render.py:
/// 195–212).
fn constraint_enum_map(constraints: Option<&serde_json::Value>) -> Option<BTreeMap<String, i64>> {
    let kind = constraint_kind(constraints)?;
    if kind != "enum" && kind != "bits" {
        return None;
    }
    let data = constraints?.as_object()?.get("data")?;
    let data = data.as_array()?;
    let mut result = BTreeMap::new();
    for item in data {
        let pair = item.as_array()?;
        if pair.len() == 2
            && let (Some(label), Some(number)) = (pair[0].as_str(), pair[1].as_i64())
        {
            result.insert(label.to_string(), number);
        }
    }
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

/// Resolves the label for `value` from a label→number map (render.py:115–126).
fn enum_label_from_map(enums: &BTreeMap<String, i64>, value: i64) -> Option<String> {
    enums
        .iter()
        .find_map(|(label, number)| (*number == value).then(|| label.clone()))
}

/// Resolves the label for `value` from an enum constraint (render.py:222–244).
fn enum_label_from_constraints(
    constraints: Option<&serde_json::Value>,
    value: i64,
) -> Option<String> {
    let kind = constraint_kind(constraints)?;
    if kind != "enum" {
        return None;
    }
    let data = constraints?.as_object()?.get("data")?;
    let data = data.as_array()?;
    for item in data {
        let pair = item.as_array()?;
        if pair.len() == 2
            && let (Some(label), Some(number)) = (pair[0].as_str(), pair[1].as_i64())
            && number == value
        {
            return Some(label.to_string());
        }
    }
    None
}

/// The object or notification node behind a match (render.py:215–219).
fn resolve_node<'a>(
    bundle: &'a MibBundle,
    match_: &OidMatch,
) -> Option<&'a crate::mib::model::MibNode> {
    bundle.resolve_node(&match_.module, &match_.symbol)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    use serde_json::json;

    use crate::mib::model::normalize_module_payload;
    use crate::mib::registry::RegistryInner;
    use crate::types::oid::Oid;

    /// Builds an in-memory bundle from module payloads (the reference's
    /// `_bundle_from_payloads`, test_mib_internals.py:120–131).
    fn bundle_from_payloads(payloads: &[&serde_json::Value]) -> MibBundle {
        let mut modules = BTreeMap::new();
        for payload in payloads {
            let record = normalize_module_payload(payload, Path::new("/virtual"))
                .expect("test payload is valid");
            modules.insert(record.module.clone(), record);
        }
        MibBundle::new(
            RegistryInner::new(modules, BTreeMap::new()),
            PathBuf::from("/virtual"),
        )
    }

    /// The reference's `_match` helper (test_mib_internals.py:133–139): a
    /// hand-rolled `OidMatch` keyed by symbol.
    fn match_for(symbol: &str, module: &str) -> OidMatch {
        let base_oid = match symbol {
            "status" => Oid::from_arcs(&[1, 3, 6, 1, 4, 1, 99999, 1]).unwrap(),
            "peerTarget" => Oid::from_arcs(&[1, 3, 6, 1, 4, 1, 99999, 2]).unwrap(),
            "statusNotice" => Oid::from_arcs(&[1, 3, 6, 1, 4, 1, 99999, 10]).unwrap(),
            "portFlags" => Oid::from_arcs(&[1, 3, 6, 1, 4, 1, 99999, 1]).unwrap(),
            _ => Oid::from_arcs(&[1, 3, 6, 1, 4, 1, 99999, 99]).unwrap(),
        };
        OidMatch {
            oid: base_oid.clone(),
            module: module.to_string(),
            symbol: symbol.to_string(),
            matched_oid: base_oid,
            suffix: Oid::empty(),
            class_name: None,
            object_type: None,
            nodetype: None,
        }
    }

    /// The APP-MIB payload builder (test_mib_internals.py:_app_payload).
    fn app_payload(
        syntax: Option<&str>,
        imports: Option<&serde_json::Value>,
        node_constraints: Option<&serde_json::Value>,
        include_local_type: bool,
    ) -> serde_json::Value {
        let imports = imports
            .cloned()
            .unwrap_or_else(|| json!({"ENUM-TC": ["TruthValue"]}));
        let mut payload = crate::mib::model::tests::test_base_module("APP-MIB", &imports);
        let mut status_node = json!({
            "oid": "1.3.6.1.4.1.99999.1",
            "oid_path": [1, 3, 6, 1, 4, 1, 99999, 1],
            "object_type": "OBJECT-TYPE",
            "class": "objecttype",
            "nodetype": "scalar",
            "max_access": "read-only",
            "status": "current",
        });
        if let Some(syntax) = syntax {
            status_node["syntax"] = serde_json::Value::String(syntax.to_string());
        }
        if let Some(constraints) = node_constraints {
            status_node["constraints"] = constraints.clone();
        }
        payload["objects"] = json!({
            "status": status_node,
            "peerTarget": {
                "oid": "1.3.6.1.4.1.99999.2",
                "oid_path": [1, 3, 6, 1, 4, 1, 99999, 2],
                "object_type": "OBJECT-TYPE",
                "class": "objecttype",
                "nodetype": "scalar",
                "syntax": "OBJECT IDENTIFIER",
                "max_access": "read-only",
                "status": "current",
            },
        });
        payload["notifications"] = json!({
            "statusNotice": {
                "oid": "1.3.6.1.4.1.99999.10",
                "oid_path": [1, 3, 6, 1, 4, 1, 99999, 10],
                "object_type": "NOTIFICATION-TYPE",
                "class": "notificationtype",
                "status": "current",
            }
        });
        if include_local_type {
            payload["types"] = json!({
                "LocalFlag": {
                    "class": "textualconvention",
                    "base_type": "Integer32",
                    "status": "current",
                }
            });
        }
        payload
    }

    fn base_module(module: &str) -> serde_json::Value {
        crate::mib::model::tests::test_base_module(module, &json!({}))
    }

    #[test]
    fn render_enum_helpers_cover_missing_node_missing_type_and_invalid_constraints() {
        let no_syntax_bundle = bundle_from_payloads(&[&app_payload(None, None, None, false)]);
        let missing_type_bundle = bundle_from_payloads(&[&app_payload(
            Some("MissingType"),
            Some(&json!({})),
            None,
            false,
        )]);
        let constrained_bundle = bundle_from_payloads(&[&app_payload(
            None,
            None,
            Some(&json!({"kind": "enum", "data": [["up", 1]]})),
            false,
        )]);

        assert_eq!(
            resolve_node(&no_syntax_bundle, &match_for("statusNotice", "APP-MIB"))
                .unwrap()
                .name,
            "statusNotice"
        );
        assert!(resolve_node(&no_syntax_bundle, &match_for("status", "MISSING")).is_none());
        assert_eq!(
            resolve_enum_label(&no_syntax_bundle, &match_for("missing", "APP-MIB"), 1),
            None
        );
        assert_eq!(
            resolve_enum_label(&no_syntax_bundle, &match_for("status", "APP-MIB"), 1),
            None
        );
        assert_eq!(
            resolve_enum_label(&missing_type_bundle, &match_for("status", "APP-MIB"), 1),
            None
        );
        assert_eq!(
            resolve_enum_label(&constrained_bundle, &match_for("status", "APP-MIB"), 1),
            Some("up".to_string())
        );

        assert_eq!(
            enum_label_from_constraints(Some(&json!({"kind": "range", "data": []})), 1),
            None
        );
        assert_eq!(
            enum_label_from_constraints(Some(&json!({"kind": "enum", "data": [["up", 1]]})), 2),
            None
        );
    }

    #[test]
    fn bits_helpers_cover_missing_nodes_and_non_bits_objects() {
        let bundle = bundle_from_payloads(&[&app_payload(Some("INTEGER"), None, None, false)]);

        assert_eq!(
            resolve_bits_labels(&bundle, &match_for("missing", "APP-MIB"), b"\x80"),
            None
        );
        assert_eq!(
            resolve_bits_labels(&bundle, &match_for("status", "APP-MIB"), b"\x80"),
            None
        );
        assert_eq!(
            constraint_enum_map(Some(&json!({"kind": "range", "data": []}))),
            None
        );
        assert_eq!(
            constraint_enum_map(Some(&json!({"kind": "enum", "data": "bad"}))),
            None
        );
        assert_eq!(constraint_enum_map(None), None);
        assert_eq!(constraint_kind(Some(&json!({"kind": 3}))), None);
        assert_eq!(enum_label_from_map(&BTreeMap::new(), 1), None);
    }

    #[test]
    fn bits_helpers_cover_inline_bits_and_tc_edges() {
        let inline_bits = app_payload(
            Some("BITS"),
            None,
            Some(&json!({"kind": "bits", "data": [["red", 0], ["green", 1]]})),
            false,
        );
        let inline_bundle = bundle_from_payloads(&[&inline_bits]);
        let inline_node = resolve_node(&inline_bundle, &match_for("status", "APP-MIB")).unwrap();
        assert_eq!(
            bits_enum_map(&inline_bundle, &match_for("status", "APP-MIB"), inline_node),
            Some(BTreeMap::from([
                ("red".to_string(), 0),
                ("green".to_string(), 1)
            ]))
        );

        let bare_bits = app_payload(Some("BITS"), None, None, false);
        let bare_bundle = bundle_from_payloads(&[&bare_bits]);
        let bare_node = resolve_node(&bare_bundle, &match_for("status", "APP-MIB")).unwrap();
        assert_eq!(
            bits_enum_map(&bare_bundle, &match_for("status", "APP-MIB"), bare_node),
            None
        );
        assert_eq!(
            resolve_bits_labels(&bare_bundle, &match_for("status", "APP-MIB"), b"\x80"),
            None
        );

        let no_syntax = bundle_from_payloads(&[&app_payload(None, None, None, false)]);
        let no_syntax_node = resolve_node(&no_syntax, &match_for("status", "APP-MIB")).unwrap();
        assert_eq!(
            bits_enum_map(&no_syntax, &match_for("status", "APP-MIB"), no_syntax_node),
            None
        );
        assert!(!is_bits_node(
            &no_syntax,
            &match_for("status", "APP-MIB"),
            no_syntax_node
        ));

        let mut tc_payload = base_module("BITS-TC");
        tc_payload["types"] = json!({
            "PortFlags": {
                "class": "textualconvention",
                "base_type": "BITS",
                "status": "current",
                "constraints": {"kind": "bits", "data": [["red", 0]]},
            }
        });
        let mut tc_app = base_module("APP-MIB");
        tc_app["imports"] = json!({"BITS-TC": ["PortFlags"]});
        tc_app["objects"] = json!({
            "portFlags": {
                "oid": "1.3.6.1.4.1.99999.1",
                "oid_path": [1, 3, 6, 1, 4, 1, 99999, 1],
                "object_type": "OBJECT-TYPE",
                "class": "objecttype",
                "nodetype": "scalar",
                "syntax": "PortFlags",
                "max_access": "read-only",
                "status": "current",
                "enums": {"red": 0, "green": 1},
            }
        });
        let tc_bundle = bundle_from_payloads(&[&tc_payload, &tc_app]);
        let tc_node = resolve_node(&tc_bundle, &match_for("portFlags", "APP-MIB")).unwrap();
        assert!(is_bits_node(
            &tc_bundle,
            &match_for("portFlags", "APP-MIB"),
            tc_node
        ));
        assert_eq!(
            bits_enum_map(&tc_bundle, &match_for("portFlags", "APP-MIB"), tc_node),
            Some(BTreeMap::from([
                ("red".to_string(), 0),
                ("green".to_string(), 1)
            ]))
        );
        assert_eq!(
            resolve_bits_labels(&tc_bundle, &match_for("portFlags", "APP-MIB"), b"\x80"),
            Some(vec![("red".to_string(), 0)])
        );
    }
}
