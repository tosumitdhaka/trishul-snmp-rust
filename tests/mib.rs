//! MIB bundle tests: loading, registry semantics, iteration/search, rendering,
//! and the vendored bundle end-to-end path. Ported from the reference's
//! test_bundle_loading.py, test_bundle_iteration.py, test_mib_internals.py,
//! test_rendering.py, test_alias_bundle.py, and test_mib_tsmi_e2e.py (the last
//! re-specified against the vendored fixtures/bundles because it compiles a
//! MIB with the Python `trishul-smi` tool).

mod common;

use std::str::FromStr;

use common::mib::{
    TempDir, app_payload, base_module, enums_node, if_mib_payload, snmpv2_tc_payload,
    test_app_payload, test_tc_payload, valid_node, valid_type, vendored_bundles, write_json,
    write_multi_module_bundle, write_scalar_instance_alias_bundle, write_value_metadata_bundle,
};
use serde_json::json;
use trishul_snmp::error::{BundleError, Error, TranslationError};
use trishul_snmp::mib::MibBundle;
use trishul_snmp::mib::load_bundle;
use trishul_snmp::mib::model::{
    MibMemberRef, normalize_module_metadata, normalize_module_payload, normalize_node_map,
    normalize_type_map,
};
use trishul_snmp::mib::render::enrich_varbinds;
use trishul_snmp::target::Target;
use trishul_snmp::types::oid::Oid;
use trishul_snmp::types::value::SnmpValue;
use trishul_snmp::types::varbind::VarBind;

fn oid(arcs: &[u32]) -> Oid {
    Oid::from_arcs(arcs).unwrap()
}

/// Loads a bundle, unwrapping the top-level error.
fn load(path: impl AsRef<std::path::Path>) -> MibBundle {
    load_bundle(path).expect("bundle loads")
}

/// True for any `BundleError::Validation` (the reference's
/// `BundleValidationError`).
fn is_validation(err: &Error) -> bool {
    matches!(err, Error::Bundle(BundleError::Validation { .. }))
}

/// Writes one module payload per module name into `dir` and loads it
/// (the reference's `_bundle_from_payloads` through the loader).
fn bundle_from_payloads(dir: &TempDir, payloads: &[&serde_json::Value]) -> MibBundle {
    for payload in payloads {
        let module = payload["module"].as_str().expect("module name");
        write_json(&dir.path().join(format!("{module}.json")), payload);
    }
    load(dir.path())
}

/// A bundle from a single APP-MIB payload variant.
fn app_bundle(dir: &TempDir, payload: &serde_json::Value) -> MibBundle {
    bundle_from_payloads(dir, &[payload])
}

fn vb(arcs: &[u32], value: SnmpValue) -> VarBind {
    VarBind::new(oid(arcs), value)
}

// ── bundle loading (test_bundle_loading.py) ─────────────────────────────────

#[test]
fn load_bundle_from_single_module_json_file() {
    let tmp = TempDir::new("single");
    write_json(&tmp.path().join("IF-MIB.json"), &if_mib_payload(true));
    let bundle = load(tmp.path().join("IF-MIB.json"));

    assert_eq!(
        bundle.translate("IF-MIB::ifDescr").unwrap(),
        "1.3.6.1.2.1.2.2.1.2"
    );
    assert_eq!(
        bundle.translate("IF-MIB::ifDescr.1").unwrap(),
        "1.3.6.1.2.1.2.2.1.2.1"
    );
    assert_eq!(
        bundle.translate("1.3.6.1.2.1.2.2.1.2.1").unwrap(),
        "IF-MIB::ifDescr.1"
    );

    let match_ = bundle
        .lookup(&oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 7]))
        .unwrap();
    assert_eq!(match_.symbolic(), "IF-MIB::ifIndex.7");
}

#[test]
fn load_bundle_retains_description_and_members_metadata() {
    let mut payload = if_mib_payload(true);
    payload["objects"]["ifDescr"]["description"] = json!("A textual description of the interface.");
    payload["notifications"] = json!({
        "linkDown": {
            "oid": "1.3.6.1.6.3.1.1.5.3",
            "oid_path": [1, 3, 6, 1, 6, 3, 1, 1, 5, 3],
            "object_type": "NOTIFICATION-TYPE",
            "class": "notificationtype",
            "status": "current",
            "description": "The agent has detected that the ifOperStatus object is down.",
            "members": [
                {"module": "IF-MIB", "object": "ifIndex"},
                {"module": "IF-MIB", "object": "ifDescr"},
            ],
        }
    });
    let tmp = TempDir::new("desc");
    write_json(&tmp.path().join("IF-MIB.json"), &payload);
    let bundle = load(tmp.path().join("IF-MIB.json"));

    let if_descr = &bundle.modules()["IF-MIB"].objects["ifDescr"];
    let link_down = &bundle.modules()["IF-MIB"].notifications["linkDown"];
    assert_eq!(
        if_descr.description.as_deref(),
        Some("A textual description of the interface.")
    );
    assert_eq!(
        link_down.description.as_deref(),
        Some("The agent has detected that the ifOperStatus object is down.")
    );
    assert_eq!(
        link_down.members.as_ref().map(|members| members
            .iter()
            .map(MibMemberRef::symbolic)
            .collect::<Vec<_>>()),
        Some(vec![
            "IF-MIB::ifIndex".to_string(),
            "IF-MIB::ifDescr".to_string()
        ])
    );
}

#[test]
fn directory_bundle_uses_manifest_inventory() {
    let tmp = TempDir::new("manifest");
    write_json(&tmp.path().join("IF-MIB.json"), &if_mib_payload(true));
    write_json(&tmp.path().join("SNMPv2-TC.json"), &snmpv2_tc_payload());
    std::fs::write(tmp.path().join("IGNORED.json"), "{not-valid-json").unwrap();
    write_json(
        &tmp.path().join("manifest.json"),
        &json!({
            "schema_version": "1",
            "producer_version": "0.4.0",
            "generated_by": "trishul-smi",
            "generated_at": "2026-05-06T12:00:00Z",
            "modules": [
                {"module": "IF-MIB", "file": "IF-MIB.json"},
                {"module": "SNMPv2-TC", "file": "SNMPv2-TC.json"},
            ],
            "artifacts": {"oid_index": "oid_index.json"},
        }),
    );
    write_json(
        &tmp.path().join("oid_index.json"),
        &json!({
            "schema_version": "1",
            "producer_version": "0.4.0",
            "generated_by": "trishul-smi",
            "generated_at": "2026-05-06T12:00:00Z",
            "oids": {
                "1.3.6.1.2.1.2.2.1.2": {
                    "module": "IF-MIB",
                    "object": "ifDescr",
                    "class": "objecttype",
                }
            },
        }),
    );

    let bundle = load(tmp.path());

    let module_names: Vec<&str> = bundle.modules().keys().map(String::as_str).collect();
    assert_eq!(module_names, vec!["IF-MIB", "SNMPv2-TC"]);
    assert_eq!(
        bundle.translate("1.3.6.1.2.1.2.2.1.2.5").unwrap(),
        "IF-MIB::ifDescr.5"
    );
    assert!(bundle.resolve_type("IF-MIB", "DisplayString").is_some());
}

#[test]
fn directory_bundle_without_manifest_ignores_sidecars() {
    let tmp = TempDir::new("nosidecar");
    write_json(&tmp.path().join("IF-MIB.json"), &if_mib_payload(true));
    write_json(
        &tmp.path().join("oid_index.json"),
        &json!({
            "1.3.6.1.2.1.2.2.1.2": {
                "module": "IF-MIB",
                "object": "ifDescr",
                "class": "objecttype",
            }
        }),
    );

    let bundle = load(tmp.path());

    let module_names: Vec<&str> = bundle.modules().keys().map(String::as_str).collect();
    assert_eq!(module_names, vec!["IF-MIB"]);
    assert_eq!(
        bundle.translate("1.3.6.1.2.1.2.2.1.2.9").unwrap(),
        "IF-MIB::ifDescr.9"
    );
}

#[test]
fn missing_dependency_modules_do_not_block_load() {
    let tmp = TempDir::new("nodeps");
    write_json(&tmp.path().join("IF-MIB.json"), &if_mib_payload(true));
    let bundle = load(tmp.path().join("IF-MIB.json"));

    assert_eq!(
        bundle.translate("IF-MIB::ifTable").unwrap(),
        "1.3.6.1.2.1.2.2"
    );
    assert!(bundle.resolve_type("IF-MIB", "DisplayString").is_none());
}

#[test]
fn invalid_generated_by_fails_validation() {
    let mut payload = if_mib_payload(true);
    payload["generated_by"] = json!("someone-else");
    let tmp = TempDir::new("producer");
    write_json(&tmp.path().join("IF-MIB.json"), &payload);

    let err = load_bundle(tmp.path().join("IF-MIB.json")).unwrap_err();
    assert!(is_validation(&err), "{err}");
}

#[test]
fn unknown_symbol_raises_error() {
    let tmp = TempDir::new("unknown");
    write_json(&tmp.path().join("IF-MIB.json"), &if_mib_payload(false));
    let bundle = load(tmp.path().join("IF-MIB.json"));

    let target = Target::from_str("IF-MIB::doesNotExist").unwrap();
    let err = bundle.resolve(&target).unwrap_err();
    assert!(err.to_string().contains("Unknown symbolic target"), "{err}");
}

#[test]
fn schema_version_at_or_below_maximum_is_accepted() {
    for version in ["1.1", "1", "1.0"] {
        let mut payload = if_mib_payload(true);
        payload["schema_version"] = json!(version);
        let tmp = TempDir::new("schema-ok");
        write_json(&tmp.path().join("IF-MIB.json"), &payload);
        let bundle = load(tmp.path().join("IF-MIB.json"));
        assert_eq!(
            bundle.modules()["IF-MIB"].schema_version.as_deref(),
            Some(version)
        );
    }
}

#[test]
fn missing_schema_version_is_accepted() {
    let tmp = TempDir::new("no-schema");
    let payload = if_mib_payload(true);
    assert!(payload.get("schema_version").is_none());
    write_json(&tmp.path().join("IF-MIB.json"), &payload);
    let bundle = load(tmp.path().join("IF-MIB.json"));
    assert_eq!(bundle.modules()["IF-MIB"].schema_version, None);
}

#[test]
fn newer_schema_version_is_rejected() {
    for version in ["1.2", "2.0"] {
        let mut payload = if_mib_payload(true);
        payload["schema_version"] = json!(version);
        payload["producer_version"] = json!("9.9.9");
        let tmp = TempDir::new("schema-new");
        write_json(&tmp.path().join("IF-MIB.json"), &payload);

        let err = load_bundle(tmp.path().join("IF-MIB.json")).unwrap_err();
        let message = err.to_string();
        assert!(is_validation(&err), "{err}");
        assert!(message.contains(version), "{message}");
        assert!(message.contains("1.1"), "{message}");
        assert!(message.contains("trishul-smi"), "{message}");
        assert!(message.contains("9.9.9"), "{message}");
    }
}

#[test]
fn malformed_schema_version_is_rejected() {
    for version in [
        json!("abc"),
        json!(""),
        json!("1.1.0-beta"),
        json!(2),
        json!(1.5),
    ] {
        let mut payload = if_mib_payload(true);
        payload["schema_version"] = version;
        let tmp = TempDir::new("schema-bad");
        write_json(&tmp.path().join("IF-MIB.json"), &payload);

        let err = load_bundle(tmp.path().join("IF-MIB.json")).unwrap_err();
        assert!(is_validation(&err), "{err}");
    }
}

#[test]
fn directory_bundle_rejects_duplicate_module_names_without_manifest() {
    let tmp = TempDir::new("dup");
    write_json(&tmp.path().join("A-IF-MIB.json"), &if_mib_payload(true));
    write_json(&tmp.path().join("B-IF-MIB.json"), &if_mib_payload(true));

    let err = load_bundle(tmp.path()).unwrap_err();
    let message = err.to_string();
    assert!(is_validation(&err), "{err}");
    assert!(message.contains("IF-MIB"), "{message}");
    assert!(message.contains("A-IF-MIB.json"), "{message}");
    assert!(message.contains("B-IF-MIB.json"), "{message}");
    assert!(
        message.find("A-IF-MIB.json").unwrap() < message.find("B-IF-MIB.json").unwrap(),
        "{message}"
    );
}

#[test]
fn directory_bundle_rejects_duplicate_module_names_via_manifest() {
    let tmp = TempDir::new("dup-manifest");
    write_json(&tmp.path().join("first.json"), &if_mib_payload(true));
    write_json(&tmp.path().join("second.json"), &if_mib_payload(true));
    write_json(
        &tmp.path().join("manifest.json"),
        &json!({
            "schema_version": "1",
            "producer_version": "0.4.0",
            "generated_by": "trishul-smi",
            "generated_at": "2026-05-06T12:00:00Z",
            "modules": [
                {"module": "IF-MIB", "file": "first.json"},
                {"module": "IF-MIB", "file": "second.json"},
            ],
        }),
    );

    let err = load_bundle(tmp.path()).unwrap_err();
    let message = err.to_string();
    assert!(is_validation(&err), "{err}");
    assert!(message.contains("IF-MIB"), "{message}");
    assert!(message.contains("first.json"), "{message}");
    assert!(message.contains("second.json"), "{message}");
    assert!(
        message.find("first.json").unwrap() < message.find("second.json").unwrap(),
        "{message}"
    );
}

#[test]
fn directory_bundle_manifest_duplicate_file_reference_dedupes() {
    let tmp = TempDir::new("dedup");
    write_json(&tmp.path().join("IF-MIB.json"), &if_mib_payload(true));
    write_json(
        &tmp.path().join("manifest.json"),
        &json!({
            "schema_version": "1",
            "producer_version": "0.4.0",
            "generated_by": "trishul-smi",
            "generated_at": "2026-05-06T12:00:00Z",
            "modules": [
                {"module": "IF-MIB", "file": "IF-MIB.json"},
                {"module": "IF-MIB", "file": "IF-MIB.json"},
            ],
        }),
    );

    let bundle = load(tmp.path());
    let module_names: Vec<&str> = bundle.modules().keys().map(String::as_str).collect();
    assert_eq!(module_names, vec!["IF-MIB"]);
    assert_eq!(
        bundle.translate("IF-MIB::ifDescr").unwrap(),
        "1.3.6.1.2.1.2.2.1.2"
    );
}

#[test]
fn directory_bundle_rejects_newer_manifest_schema_version() {
    let tmp = TempDir::new("manifest-new");
    write_json(&tmp.path().join("IF-MIB.json"), &if_mib_payload(true));
    write_json(
        &tmp.path().join("manifest.json"),
        &json!({
            "schema_version": "2.0",
            "producer_version": "9.9.9",
            "generated_by": "trishul-smi",
            "generated_at": "2026-05-06T12:00:00Z",
            "modules": [{"module": "IF-MIB", "file": "IF-MIB.json"}],
        }),
    );

    let err = load_bundle(tmp.path()).unwrap_err();
    let message = err.to_string();
    assert!(is_validation(&err), "{err}");
    assert!(message.contains("2.0"), "{message}");
    assert!(message.contains("1.1"), "{message}");
    assert!(message.contains("9.9.9"), "{message}");
}

#[test]
fn manifest_paths_validation_and_dedup() {
    let tmp = TempDir::new("manifest-path");
    write_json(&tmp.path().join("IF-MIB.json"), &if_mib_payload(true));
    // A mixed string/object inventory with a duplicate reference dedupes.
    write_json(
        &tmp.path().join("manifest.json"),
        &json!({"modules": ["IF-MIB.json", {"file": "IF-MIB.json"}]}),
    );
    let bundle = load(tmp.path());
    assert_eq!(bundle.modules().len(), 1);

    // A non-object manifest is rejected.
    write_json(&tmp.path().join("manifest.json"), &json!(["IF-MIB.json"]));
    let err = load_bundle(tmp.path()).unwrap_err();
    assert!(
        err.to_string().contains("Manifest must be a JSON object"),
        "{err}"
    );

    // An empty modules list is rejected.
    write_json(&tmp.path().join("manifest.json"), &json!({"modules": []}));
    let err = load_bundle(tmp.path()).unwrap_err();
    assert!(
        err.to_string()
            .contains("Manifest is missing a valid 'modules' list"),
        "{err}"
    );

    // A traversal escape is rejected.
    write_json(
        &tmp.path().join("manifest.json"),
        &json!({"modules": ["../outside.json"]}),
    );
    let err = load_bundle(tmp.path()).unwrap_err();
    assert!(
        err.to_string()
            .contains("Manifest module file must stay within the bundle directory"),
        "{err}"
    );

    // A missing referenced file is rejected.
    write_json(
        &tmp.path().join("manifest.json"),
        &json!({"modules": ["MISSING.json"]}),
    );
    let err = load_bundle(tmp.path()).unwrap_err();
    assert!(
        err.to_string()
            .contains("Manifest references a missing module file"),
        "{err}"
    );

    // A module entry without a file field is rejected.
    write_json(
        &tmp.path().join("manifest.json"),
        &json!({"modules": [{"module": "IF-MIB"}]}),
    );
    let err = load_bundle(tmp.path()).unwrap_err();
    assert!(
        err.to_string()
            .contains("Manifest modules must be strings or objects containing a 'file' field"),
        "{err}"
    );
}

#[cfg(unix)]
#[test]
fn manifest_symlink_escape_is_rejected() {
    use std::os::unix::fs::symlink;

    // A module file living outside the bundle directory, referenced through a
    // symlink inside it: Python's `Path.resolve()` follows the link and the
    // containment check rejects it (loader.py:128–133); the Rust loader
    // canonicalizes the same way.
    let outside = TempDir::new("symlink-outside");
    write_json(&outside.path().join("IF-MIB.json"), &if_mib_payload(true));
    let tmp = TempDir::new("symlink-escape");
    symlink(
        outside.path().join("IF-MIB.json"),
        tmp.path().join("IF-MIB.json"),
    )
    .unwrap();
    write_json(
        &tmp.path().join("manifest.json"),
        &json!({"modules": ["IF-MIB.json"]}),
    );

    let err = load_bundle(tmp.path()).unwrap_err();
    assert!(
        err.to_string()
            .contains("Manifest module file must stay within the bundle directory"),
        "{err}"
    );
}

#[test]
fn oid_index_validation_errors() {
    let tmp = TempDir::new("oididx");
    write_json(&tmp.path().join("IF-MIB.json"), &if_mib_payload(true));

    // A non-object index is rejected.
    write_json(&tmp.path().join("oid_index.json"), &json!([]));
    let err = load_bundle(tmp.path()).unwrap_err();
    assert!(
        err.to_string().contains("OID index must be a JSON object"),
        "{err}"
    );

    // A non-object "oids" payload is rejected.
    write_json(&tmp.path().join("oid_index.json"), &json!({"oids": []}));
    let err = load_bundle(tmp.path()).unwrap_err();
    assert!(
        err.to_string()
            .contains("OID index entries must be a JSON object"),
        "{err}"
    );

    // A non-object entry is rejected.
    write_json(&tmp.path().join("oid_index.json"), &json!({"1.3.6": []}));
    let err = load_bundle(tmp.path()).unwrap_err();
    assert!(
        err.to_string()
            .contains("OID index entries must be JSON objects"),
        "{err}"
    );

    // A missing object field is rejected.
    write_json(
        &tmp.path().join("oid_index.json"),
        &json!({"1.3.6": {"module": "APP-MIB"}}),
    );
    let err = load_bundle(tmp.path()).unwrap_err();
    assert!(
        err.to_string()
            .contains("OID index entries must contain string 'module' and 'object' fields"),
        "{err}"
    );

    // A malformed OID key is rejected. (The reference's non-string-key case —
    // a Python dict with an int key — is impossible in JSON, where object
    // keys are always strings; this malformed-string-key case is the JSON
    // equivalent, see docs/architecture.md §8.)
    write_json(
        &tmp.path().join("oid_index.json"),
        &json!({"not-an-oid": {"module": "APP-MIB", "object": "status"}}),
    );
    let err = load_bundle(tmp.path()).unwrap_err();
    assert!(is_validation(&err), "{err}");
}

// ── bundle iteration and search (test_bundle_iteration.py) ──────────────────

fn multi_module_bundle(tmp: &TempDir) -> MibBundle {
    write_multi_module_bundle(tmp.path());
    load(tmp.path())
}

#[test]
fn iter_objects_returns_all_objects() {
    let tmp = TempDir::new("iter");
    let bundle = multi_module_bundle(&tmp);
    let names: std::collections::BTreeSet<&str> = bundle
        .iter_objects(None, None)
        .map(|node| node.name.as_str())
        .collect();
    assert_eq!(
        names,
        ["sysDescr", "ifIndex", "sysUpTime"].into_iter().collect()
    );
}

#[test]
fn iter_objects_filters_by_module() {
    let tmp = TempDir::new("iter-mod");
    let bundle = multi_module_bundle(&tmp);
    let names: std::collections::BTreeSet<&str> = bundle
        .iter_objects(Some("MIB-A"), None)
        .map(|node| node.name.as_str())
        .collect();
    assert_eq!(names, ["sysDescr", "ifIndex"].into_iter().collect());
}

#[test]
fn iter_objects_filters_by_type_filter() {
    let tmp = TempDir::new("iter-type");
    let bundle = multi_module_bundle(&tmp);
    let nodes: Vec<_> = bundle.iter_objects(None, Some("OBJECT-TYPE")).collect();
    assert!(nodes.iter().all(|node| node.object_type == "OBJECT-TYPE"));
    assert_eq!(nodes.len(), 3);
}

#[test]
fn iter_objects_module_and_type_filter_combined() {
    let tmp = TempDir::new("iter-both");
    let bundle = multi_module_bundle(&tmp);
    let names: Vec<&str> = bundle
        .iter_objects(Some("MIB-B"), Some("OBJECT-TYPE"))
        .map(|node| node.name.as_str())
        .collect();
    assert_eq!(names, vec!["sysUpTime"]);
}

#[test]
fn iter_objects_empty_for_unknown_module() {
    let tmp = TempDir::new("iter-none");
    let bundle = multi_module_bundle(&tmp);
    assert_eq!(bundle.iter_objects(Some("NO-SUCH-MIB"), None).count(), 0);
}

#[test]
fn iter_notifications_returns_all_notifications() {
    let tmp = TempDir::new("notifs");
    let bundle = multi_module_bundle(&tmp);
    let names: std::collections::BTreeSet<&str> = bundle
        .iter_notifications(None)
        .map(|node| node.name.as_str())
        .collect();
    assert_eq!(names, ["linkDown", "linkUp"].into_iter().collect());
}

#[test]
fn iter_notifications_filters_by_module() {
    let tmp = TempDir::new("notifs-mod");
    let bundle = multi_module_bundle(&tmp);
    let names: Vec<&str> = bundle
        .iter_notifications(Some("MIB-A"))
        .map(|node| node.name.as_str())
        .collect();
    assert_eq!(names, vec!["linkDown"]);
}

#[test]
fn iter_notifications_empty_for_unknown_module() {
    let tmp = TempDir::new("notifs-none");
    let bundle = multi_module_bundle(&tmp);
    assert_eq!(bundle.iter_notifications(Some("NO-SUCH-MIB")).count(), 0);
}

#[test]
fn search_matches_name_substring() {
    let tmp = TempDir::new("search-name");
    let bundle = multi_module_bundle(&tmp);
    let names: std::collections::BTreeSet<&str> = bundle
        .search("sys", None, None, 100)
        .into_iter()
        .map(|node| node.name.as_str())
        .collect();
    assert!(names.contains("sysDescr"), "{names:?}");
    assert!(names.contains("sysUpTime"), "{names:?}");
}

#[test]
fn search_matches_description_substring() {
    let tmp = TempDir::new("search-desc");
    let bundle = multi_module_bundle(&tmp);
    let results = bundle.search("uptime", None, None, 100);
    assert!(results.iter().any(|node| node.name == "sysUpTime"));
}

#[test]
fn search_is_case_insensitive() {
    let tmp = TempDir::new("search-case");
    let bundle = multi_module_bundle(&tmp);
    let lower: std::collections::BTreeSet<&str> = bundle
        .search("link", None, None, 100)
        .into_iter()
        .map(|node| node.name.as_str())
        .collect();
    let upper: std::collections::BTreeSet<&str> = bundle
        .search("LINK", None, None, 100)
        .into_iter()
        .map(|node| node.name.as_str())
        .collect();
    assert_eq!(lower, upper);
    assert!(lower.contains("linkDown"));
    assert!(lower.contains("linkUp"));
}

#[test]
fn search_filters_by_module() {
    let tmp = TempDir::new("search-mod");
    let bundle = multi_module_bundle(&tmp);
    let names: Vec<&str> = bundle
        .search("sys", Some("MIB-B"), None, 100)
        .into_iter()
        .map(|node| node.name.as_str())
        .collect();
    assert_eq!(names, vec!["sysUpTime"]);
}

#[test]
fn search_type_filter_objects_only() {
    let tmp = TempDir::new("search-obj");
    let bundle = multi_module_bundle(&tmp);
    assert_eq!(
        bundle.search("link", None, Some("OBJECT-TYPE"), 100).len(),
        0
    );
}

#[test]
fn search_type_filter_notifications_only() {
    let tmp = TempDir::new("search-notif");
    let bundle = multi_module_bundle(&tmp);
    let names: std::collections::BTreeSet<&str> = bundle
        .search("link", None, Some("NOTIFICATION-TYPE"), 100)
        .into_iter()
        .map(|node| node.name.as_str())
        .collect();
    assert_eq!(names, ["linkDown", "linkUp"].into_iter().collect());
}

#[test]
fn search_respects_limit() {
    let tmp = TempDir::new("search-limit");
    let bundle = multi_module_bundle(&tmp);
    assert!(bundle.search("", None, None, 2).len() <= 2);
}

#[test]
fn search_returns_empty_for_no_match() {
    let tmp = TempDir::new("search-none");
    let bundle = multi_module_bundle(&tmp);
    assert_eq!(bundle.search("zzznomatch", None, None, 100).len(), 0);
}

// ── mib internals (test_mib_internals.py) ───────────────────────────────────

#[test]
fn mibnode_symbolic_and_enrich_varbinds_without_bundle() {
    let path = std::path::Path::new("/virtual/APP-MIB.json");
    let nodes = normalize_node_map(
        Some(&json!({
            "status": {
                "oid": "1.3.6.1.4.1.99999.1",
                "oid_path": [1, 3, 6, 1, 4, 1, 99999, 1],
                "object_type": "OBJECT-TYPE",
                "class": "objecttype",
                "nodetype": "scalar",
                "syntax": "TruthValue",
                "max_access": "read-only",
                "status": "current",
            }
        })),
        "APP-MIB",
        path,
        None,
    )
    .unwrap();
    assert_eq!(nodes["status"].symbolic(), "APP-MIB::status");

    let enriched = enrich_varbinds(None, vec![vb(&[1, 3, 6, 1], SnmpValue::Integer(7))]);
    assert_eq!(enriched[0].display_name, None);
    assert_eq!(enriched[0].display_value.as_deref(), Some("7"));
}

#[test]
fn normalize_node_map_retains_description_and_members() {
    let path = std::path::Path::new("/virtual/APP-MIB.json");
    let normalized = normalize_node_map(
        Some(&json!({
            "statusNotice": {
                "oid": "1.3.6.1.4.1.99999.10",
                "oid_path": [1, 3, 6, 1, 4, 1, 99999, 10],
                "object_type": "NOTIFICATION-TYPE",
                "class": "notificationtype",
                "status": "current",
                "description": "Status changed notification.",
                "members": [
                    {"module": "APP-MIB", "object": "status"},
                    {"module": "APP-MIB", "object": "peerTarget"},
                ],
            },
        })),
        "APP-MIB",
        path,
        Some("notification"),
    )
    .unwrap();

    let node = &normalized["statusNotice"];
    assert_eq!(node.nodetype.as_deref(), Some("notification"));
    assert_eq!(
        node.description.as_deref(),
        Some("Status changed notification.")
    );
    assert_eq!(
        node.members,
        Some(vec![
            MibMemberRef {
                module: "APP-MIB".to_string(),
                object: "status".to_string(),
            },
            MibMemberRef {
                module: "APP-MIB".to_string(),
                object: "peerTarget".to_string(),
            },
        ])
    );
}

#[test]
fn rendering_falls_back_for_unknown_oid_lookup_and_untranslated_oid_value() {
    let tmp = TempDir::new("fallback");
    let bundle = app_bundle(&tmp, &app_payload(None, None, None, false));
    let varbinds = vec![
        vb(&[1, 3, 6, 1, 4, 1, 99999, 99, 0], SnmpValue::Integer(9)),
        vb(
            &[1, 3, 6, 1, 4, 1, 99999, 98, 0],
            SnmpValue::ObjectIdentifier(oid(&[1, 3, 6, 1, 4, 1, 99999, 200])),
        ),
    ];

    let enriched = enrich_varbinds(Some(&bundle), varbinds);
    assert_eq!(enriched[0].display_name, None);
    assert_eq!(enriched[0].display_value.as_deref(), Some("9"));
    assert_eq!(enriched[1].display_name, None);
    assert_eq!(
        enriched[1].display_value.as_deref(),
        Some("1.3.6.1.4.1.99999.200")
    );
}

#[test]
fn parse_oid_variants_and_errors() {
    assert_eq!(Oid::parse(" .1.3.6 ").unwrap().arcs(), &[1, 3, 6]);
    for bad in ["", ".", "1.two", "1.-1"] {
        assert!(Oid::parse(bad).is_err(), "{bad:?} should fail");
    }
}

#[test]
fn parse_symbolic_target_and_translation_edges() {
    let target = Target::from_str("APP-MIB::status.7").unwrap();
    let tmp = TempDir::new("symbolic");
    let payload = app_payload(None, Some(&json!({"ENUM-TC": ["TruthValue"]})), None, true);
    let bundle = app_bundle(&tmp, &payload);

    assert_eq!(
        bundle.resolve(&target).unwrap(),
        oid(&[1, 3, 6, 1, 4, 1, 99999, 1, 7])
    );
    for bad in ["APP-MIB", "APP-MIB::.1", "APP-MIB::status.foo"] {
        assert!(
            Target::from_str(bad).is_err(),
            "{bad:?} should fail symbolic parsing"
        );
    }

    assert!(bundle.resolve_type("APP-MIB", "LocalFlag").is_some());
    assert!(bundle.resolve_type("MISSING", "LocalFlag").is_none());
    assert!(bundle.resolve_type("APP-MIB", "TruthValue").is_none());

    let err = bundle.translate("   ").unwrap_err();
    assert!(matches!(err, Error::Translation(_)), "{err}");
    let err = bundle
        .lookup(&oid(&[1, 3, 6, 1, 4, 1, 99999, 250]))
        .unwrap_err();
    assert!(
        matches!(err, Error::Translation(TranslationError::UnknownOid(_))),
        "{err:?}"
    );
}

#[test]
fn normalize_imports_validation_errors() {
    let path = std::path::Path::new("/virtual/x.json");
    let payload = base_module("APP-MIB", None);
    let mut bad_list = payload.clone();
    bad_list["imports"] = json!([]);
    assert!(normalize_module_payload(&bad_list, path).is_err());

    let mut bad_names = payload.clone();
    bad_names["imports"] = json!({"MOD": "name"});
    assert!(normalize_module_payload(&bad_names, path).is_err());
}

#[test]
fn normalize_node_map_validation_errors() {
    let path = std::path::Path::new("/virtual/x.json");

    assert!(normalize_node_map(Some(&json!([])), "APP-MIB", path, None).is_err());
    assert!(normalize_node_map(Some(&json!({"node": []})), "APP-MIB", path, None).is_err());
    assert!(
        normalize_node_map(
            Some(&json!({"node": valid_node(&json!({"index": [1]}))})),
            "APP-MIB",
            path,
            None,
        )
        .is_err()
    );
    assert!(
        normalize_node_map(
            Some(&json!({"node": valid_node(&json!({"constraints": ["bad"]}))})),
            "APP-MIB",
            path,
            None,
        )
        .is_err()
    );
    assert!(
        normalize_node_map(
            Some(&json!({"node": valid_node(&json!({"description": 1}))})),
            "APP-MIB",
            path,
            None,
        )
        .is_err()
    );
    assert!(
        normalize_node_map(
            Some(&json!({"node": valid_node(&json!({"members": "bad"}))})),
            "APP-MIB",
            path,
            None,
        )
        .is_err()
    );
    assert!(normalize_node_map(
        Some(&json!({"node": valid_node(&json!({"members": [{"module": "APP-MIB", "object": 1}]}))})),
        "APP-MIB",
        path,
        None,
    ).is_err());
}

#[test]
fn normalize_type_map_validation_errors() {
    let path = std::path::Path::new("/virtual/x.json");

    assert!(normalize_type_map(Some(&json!([])), "APP-MIB", path).is_err());
    assert!(normalize_type_map(Some(&json!({"Type": []})), "APP-MIB", path).is_err());
    assert!(
        normalize_type_map(
            Some(&json!({"Type": valid_type(&json!({"constraints": ["bad"]}))})),
            "APP-MIB",
            path,
        )
        .is_err()
    );
}

#[test]
fn normalize_node_oid_and_string_helpers_validation_errors() {
    let path = std::path::Path::new("/virtual/x.json");

    // oid-only nodes normalize (the `_normalize_node_oid(None, "1.3.6.1")`
    // path).
    let nodes = normalize_node_map(
        Some(&json!({"node": {"oid": "1.3.6.1", "object_type": "OBJECT-TYPE", "class": "objecttype"}})),
        "APP-MIB",
        path,
        None,
    )
    .unwrap();
    assert_eq!(nodes["node"].oid, oid(&[1, 3, 6, 1]));

    // A non-list oid_path is rejected.
    assert!(
        normalize_node_map(
            Some(&json!({"node": valid_node(&json!({"oid_path": "bad"}))})),
            "APP-MIB",
            path,
            None,
        )
        .is_err()
    );
    // Inconsistent oid and oid_path are rejected.
    assert!(
        normalize_node_map(
            Some(&json!({"node": valid_node(&json!({"oid": "1.3.6.2"}))})),
            "APP-MIB",
            path,
            None,
        )
        .is_err()
    );
    // Missing both oid_path and oid is rejected.
    let mut bare = valid_node(&json!({}));
    bare.as_object_mut().unwrap().remove("oid");
    bare.as_object_mut().unwrap().remove("oid_path");
    assert!(normalize_node_map(Some(&json!({"node": bare})), "APP-MIB", path, None,).is_err());
    // Missing required class is rejected.
    let mut no_class = valid_node(&json!({}));
    no_class.as_object_mut().unwrap().remove("class");
    assert!(normalize_node_map(Some(&json!({"node": no_class})), "APP-MIB", path, None,).is_err());
    // A non-string optional field is rejected.
    assert!(
        normalize_node_map(
            Some(&json!({"node": valid_node(&json!({"syntax": 1}))})),
            "APP-MIB",
            path,
            None,
        )
        .is_err()
    );
    // A malformed oid string alongside a valid oid_path is rejected, exactly
    // like the reference's `parse_oid(oid_value)` propagating InvalidOidError
    // (registry.py:458) — it is not silently ignored.
    assert!(
        normalize_node_map(
            Some(&json!({"node": valid_node(&json!({"oid": "not-an-oid"}))})),
            "APP-MIB",
            path,
            None,
        )
        .is_err()
    );
}

#[test]
fn normalize_module_metadata_and_payload_validation_errors() {
    let path = std::path::Path::new("/virtual/x.json");

    assert_eq!(
        normalize_module_metadata(None, path).unwrap(),
        serde_json::Value::Object(serde_json::Map::new())
    );
    assert!(normalize_module_metadata(Some(&json!([])), path).is_err());

    assert!(normalize_module_payload(&json!([]), path).is_err());
    assert!(normalize_module_payload(&json!({"generated_by": "trishul-smi"}), path,).is_err());
    assert!(normalize_module_payload(&json!({"module": "APP-MIB"}), path).is_err());
}

#[test]
fn explicit_null_collections_are_rejected() {
    // A present-`null` for imports/objects/notifications/types is rejected
    // exactly like the reference's `payload.get(key, {})` returning the
    // stored `None` (registry.py:575, 314–316, 331–333, 409–411).
    let path = std::path::Path::new("/virtual/x.json");
    for (field, message) in [
        ("imports", "Module imports must be an object"),
        ("objects", "Node collections must be an object"),
        ("notifications", "Node collections must be an object"),
        ("types", "Type collections must be an object"),
    ] {
        let mut payload = base_module("APP-MIB", None);
        payload[field] = serde_json::Value::Null;
        let err = normalize_module_payload(&payload, path).unwrap_err();
        assert!(err.to_string().contains(message), "{field}: {err}");
    }
    // `module_metadata: null` is accepted by both implementations (mapped to
    // the empty object).
    let mut payload = base_module("APP-MIB", None);
    payload["module_metadata"] = serde_json::Value::Null;
    let record = normalize_module_payload(&payload, path).unwrap();
    assert_eq!(
        record.module_metadata,
        serde_json::Value::Object(serde_json::Map::new())
    );
}

#[test]
fn loader_missing_path_empty_dir_and_json_reading_helpers() {
    let tmp = TempDir::new("loader");

    let err = load_bundle(tmp.path().join("missing")).unwrap_err();
    assert!(is_validation(&err), "{err}");

    let empty = TempDir::new("empty");
    let err = load_bundle(empty.path()).unwrap_err();
    assert!(
        err.to_string()
            .contains("No module JSON files were found in bundle directory"),
        "{err}"
    );

    // A malformed module JSON surfaces as "Invalid JSON".
    std::fs::write(tmp.path().join("bad.json"), "{not-json").unwrap();
    let err = load_bundle(tmp.path()).unwrap_err();
    assert!(err.to_string().contains("Invalid JSON"), "{err}");
}

#[test]
fn build_registry_loads_distinct_modules() {
    let tmp = TempDir::new("distinct");
    write_json(&tmp.path().join("A.json"), &base_module("MIB-A", None));
    write_json(&tmp.path().join("B.json"), &base_module("MIB-B", None));
    let bundle = load(tmp.path());
    let module_names: Vec<&str> = bundle.modules().keys().map(String::as_str).collect();
    assert_eq!(module_names, vec!["MIB-A", "MIB-B"]);
}

#[test]
fn registry_accelerator_lookup_and_prefix_resolution() {
    let tmp = TempDir::new("accelerator");
    let payload = app_payload(None, None, None, false);
    write_json(&tmp.path().join("APP-MIB.json"), &payload);
    write_json(
        &tmp.path().join("oid_index.json"),
        &json!({
            "1.3.6.1.4.1.99999.2": {
                "module": "APP-MIB",
                "object": "peerTarget",
            }
        }),
    );
    let bundle = load(tmp.path());

    let exact = bundle.lookup(&oid(&[1, 3, 6, 1, 4, 1, 99999, 2])).unwrap();
    let prefixed = bundle
        .lookup(&oid(&[1, 3, 6, 1, 4, 1, 99999, 2, 7]))
        .unwrap();
    assert_eq!(exact.symbolic(), "APP-MIB::peerTarget");
    assert_eq!(prefixed.symbolic(), "APP-MIB::peerTarget.7");
}

#[test]
fn normalize_node_enums_and_units_populated() {
    let path = std::path::Path::new("/virtual/APP-MIB.json");
    let normalized = normalize_node_map(
        Some(&json!({"status": enums_node(&json!({}))})),
        "APP-MIB",
        path,
        None,
    )
    .unwrap();
    let node = &normalized["status"];
    assert_eq!(
        node.enums,
        Some(
            [("up".to_string(), 1), ("down".to_string(), 2)]
                .into_iter()
                .collect()
        )
    );
    assert_eq!(node.units.as_deref(), Some("bits/second"));
}

#[test]
fn normalize_node_missing_enums_and_units_default_to_none() {
    let path = std::path::Path::new("/virtual/APP-MIB.json");
    let normalized = normalize_node_map(
        Some(&json!({"status": valid_node(&json!({}))})),
        "APP-MIB",
        path,
        None,
    )
    .unwrap();
    assert_eq!(normalized["status"].enums, None);
    assert_eq!(normalized["status"].units, None);
}

#[test]
fn normalize_node_invalid_enums_and_units_errors() {
    let path = std::path::Path::new("/virtual/x.json");
    for bad_enums in [
        json!("bad"),
        json!(["up"]),
        json!({"up": "1"}),
        json!({"up": true}),
    ] {
        assert!(
            normalize_node_map(
                Some(&json!({"node": enums_node(&json!({"enums": bad_enums}))})),
                "APP-MIB",
                path,
                None,
            )
            .is_err(),
            "{bad_enums} should fail"
        );
    }
    assert!(
        normalize_node_map(
            Some(&json!({"node": enums_node(&json!({"units": 42}))})),
            "APP-MIB",
            path,
            None,
        )
        .is_err()
    );
}

#[test]
fn registry_lookup_metadata_enums_units_and_missing_nodes() {
    let tmp = TempDir::new("metadata");
    let mut payload = app_payload(Some("INTEGER"), None, None, false);
    payload["objects"]["status"]["enums"] = json!({"up": 1, "down": 2});
    payload["objects"]["status"]["units"] = json!("volts");
    let bundle = app_bundle(&tmp, &payload);

    let metadata = bundle.lookup_metadata(&oid(&[1, 3, 6, 1, 4, 1, 99999, 1, 0]));
    assert!(metadata.is_some());
    let metadata = metadata.unwrap();
    assert_eq!(
        metadata.enums,
        Some(
            [("up".to_string(), 1), ("down".to_string(), 2)]
                .into_iter()
                .collect()
        )
    );
    assert_eq!(metadata.units.as_deref(), Some("volts"));
    assert_eq!(metadata.syntax.as_deref(), Some("INTEGER"));

    assert!(
        bundle
            .lookup_metadata(&oid(&[1, 3, 6, 1, 4, 1, 99999, 250]))
            .is_none()
    );
}

#[test]
fn registry_lookup_metadata_unknown_accelerator_symbol_returns_none() {
    let tmp = TempDir::new("metadata-accel");
    let payload = app_payload(None, None, None, false);
    write_json(&tmp.path().join("APP-MIB.json"), &payload);
    write_json(
        &tmp.path().join("oid_index.json"),
        &json!({
            "1.3.6.1.4.1": {
                "module": "APP-MIB",
                "object": "missingSymbol",
            }
        }),
    );
    let bundle = load(tmp.path());

    assert!(
        bundle
            .lookup_metadata(&oid(&[1, 3, 6, 1, 4, 1, 7]))
            .is_none()
    );
}

#[test]
fn registry_lookup_metadata_absent_on_legacy_bundle() {
    let tmp = TempDir::new("metadata-legacy");
    let bundle = app_bundle(&tmp, &app_payload(None, None, None, false));

    let metadata = bundle.lookup_metadata(&oid(&[1, 3, 6, 1, 4, 1, 99999, 1, 0]));
    assert!(metadata.is_some());
    let metadata = metadata.unwrap();
    assert_eq!(metadata.enums, None);
    assert_eq!(metadata.units, None);
}

#[test]
fn enrich_varbinds_renders_enums_units_and_bits() {
    let tmp = TempDir::new("value-meta");
    write_value_metadata_bundle(tmp.path());
    let bundle = load(tmp.path());

    let enriched = enrich_varbinds(
        Some(&bundle),
        vec![
            vb(&[1, 3, 6, 1, 4, 1, 99999, 1, 0], SnmpValue::Integer(2)),
            vb(
                &[1, 3, 6, 1, 4, 1, 99999, 2, 0],
                SnmpValue::OctetString(vec![0xC0]),
            ),
            vb(&[1, 3, 6, 1, 4, 1, 99999, 3, 0], SnmpValue::Integer(7)),
        ],
    );

    assert_eq!(enriched[0].display_value.as_deref(), Some("down(2)"));
    assert_eq!(enriched[0].enum_label.as_deref(), Some("down"));
    assert_eq!(enriched[0].units, None);
    assert_eq!(
        enriched[1].display_value.as_deref(),
        Some("red(0) green(1)")
    );
    assert_eq!(enriched[1].enum_label, None);
    assert_eq!(enriched[1].units, None);
    assert_eq!(enriched[2].display_value.as_deref(), Some("7"));
    assert_eq!(enriched[2].enum_label, None);
    assert_eq!(enriched[2].units.as_deref(), Some("bits/second"));
}

#[test]
fn enrich_varbinds_unmatched_enum_and_raw_octet_strings() {
    let tmp = TempDir::new("value-raw");
    write_value_metadata_bundle(tmp.path());
    let bundle = load(tmp.path());

    let enriched = enrich_varbinds(
        Some(&bundle),
        vec![
            vb(&[1, 3, 6, 1, 4, 1, 99999, 1, 0], SnmpValue::Integer(99)),
            vb(
                &[1, 3, 6, 1, 4, 1, 99999, 2, 0],
                SnmpValue::OctetString(vec![0x00]),
            ),
            vb(
                &[1, 3, 6, 1, 4, 1, 99999, 5, 0],
                SnmpValue::OctetString(b"hello".to_vec()),
            ),
            vb(
                &[1, 3, 6, 1, 4, 1, 99999, 250],
                SnmpValue::OctetString(vec![0x80]),
            ),
        ],
    );

    assert_eq!(enriched[0].display_value.as_deref(), Some("99"));
    assert_eq!(enriched[0].enum_label, None);
    assert_eq!(enriched[1].display_value.as_deref(), Some("00"));
    assert_eq!(enriched[2].display_value.as_deref(), Some("hello"));
    assert_eq!(enriched[3].display_value.as_deref(), Some("80"));
}

#[test]
fn enrich_varbinds_bits_via_textual_convention() {
    let mut tc_payload = base_module("BITS-TC", None);
    tc_payload["types"] = json!({
        "PortFlags": {
            "class": "textualconvention",
            "base_type": "BITS",
            "status": "current",
            "constraints": {"kind": "bits", "data": [["red", 0], ["green", 1]]},
        }
    });
    let mut app = base_module("APP-MIB", Some(&json!({"BITS-TC": ["PortFlags"]})));
    app["objects"] = json!({
        "portFlags": {
            "oid": "1.3.6.1.4.1.99999.1",
            "oid_path": [1, 3, 6, 1, 4, 1, 99999, 1],
            "object_type": "OBJECT-TYPE",
            "class": "objecttype",
            "nodetype": "scalar",
            "syntax": "PortFlags",
            "max_access": "read-only",
            "status": "current",
        }
    });
    let tmp = TempDir::new("bits-tc");
    let bundle = bundle_from_payloads(&tmp, &[&tc_payload, &app]);

    let enriched = enrich_varbinds(
        Some(&bundle),
        vec![vb(
            &[1, 3, 6, 1, 4, 1, 99999, 1, 0],
            SnmpValue::OctetString(vec![0x80]),
        )],
    );
    assert_eq!(enriched[0].display_value.as_deref(), Some("red(0)"));
}

// ── rendering (test_rendering.py) ───────────────────────────────────────────

#[test]
fn bundle_enrichment_renders_imported_enum_labels() {
    let tmp = TempDir::new("rendering-enum");
    write_json(&tmp.path().join("TEST-TC.json"), &test_tc_payload());
    write_json(&tmp.path().join("TEST-APP-MIB.json"), &test_app_payload());
    let bundle = load(tmp.path());

    let enriched = enrich_varbinds(
        Some(&bundle),
        vec![vb(&[1, 3, 6, 1, 4, 1, 99999, 1, 0], SnmpValue::Integer(1))],
    );

    assert_eq!(
        enriched[0].display_name.as_deref(),
        Some("TEST-APP-MIB::adminStatus.0")
    );
    assert_eq!(enriched[0].display_value.as_deref(), Some("up(1)"));
}

#[test]
fn bundle_enrichment_translates_object_identifier_values() {
    let tmp = TempDir::new("rendering-oid");
    write_json(&tmp.path().join("TEST-TC.json"), &test_tc_payload());
    write_json(&tmp.path().join("TEST-APP-MIB.json"), &test_app_payload());
    let bundle = load(tmp.path());

    let enriched = enrich_varbinds(
        Some(&bundle),
        vec![vb(
            &[1, 3, 6, 1, 4, 1, 99999, 3, 0],
            SnmpValue::ObjectIdentifier(oid(&[1, 3, 6, 1, 4, 1, 99999, 2])),
        )],
    );

    assert_eq!(
        enriched[0].display_name.as_deref(),
        Some("TEST-APP-MIB::peerReference.0")
    );
    assert_eq!(
        enriched[0].display_value.as_deref(),
        Some("TEST-APP-MIB::peerTarget")
    );
}

// ── scalar-instance alias bundle (test_alias_bundle.py) ─────────────────────

#[test]
fn alias_bundle_keeps_exact_lookup_semantics() {
    let tmp = TempDir::new("alias");
    write_scalar_instance_alias_bundle(tmp.path());
    let bundle = load(tmp.path());

    let scalar = bundle.lookup(&oid(&[1, 3, 6, 1, 2, 1, 1, 3])).unwrap();
    let exact_instance = bundle.lookup(&oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0])).unwrap();

    assert_eq!(scalar.symbolic(), "SNMPv2-MIB::sysUpTime");
    assert_eq!(scalar.object_type.as_deref(), Some("OBJECT-TYPE"));
    assert_eq!(
        exact_instance.symbolic(),
        "DISMAN-EXPRESSION-MIB::sysUpTimeInstance"
    );
    assert_eq!(
        exact_instance.object_type.as_deref(),
        Some("OBJECT IDENTIFIER")
    );
    assert_eq!(
        bundle.translate("SNMPv2-MIB::sysUpTime.0").unwrap(),
        "1.3.6.1.2.1.1.3.0"
    );
    assert_eq!(
        bundle.translate("1.3.6.1.2.1.1.3.0").unwrap(),
        "SNMPv2-MIB::sysUpTime.0"
    );
}

#[test]
fn alias_bundle_prefers_parent_scalar_for_display_name() {
    let tmp = TempDir::new("alias-display");
    write_scalar_instance_alias_bundle(tmp.path());
    let bundle = load(tmp.path());

    let enriched = enrich_varbinds(
        Some(&bundle),
        vec![vb(&[1, 3, 6, 1, 2, 1, 1, 3, 0], SnmpValue::TimeTicks(123))],
    );

    assert_eq!(
        enriched[0].display_name.as_deref(),
        Some("SNMPv2-MIB::sysUpTime.0")
    );
    assert_eq!(enriched[0].display_value.as_deref(), Some("123"));
}

// ── vendored bundles end-to-end (re-spec of test_mib_tsmi_e2e.py) ───────────
//
// The reference suite compiles a MIB with the Python `trishul-smi` tool; the
// Rust port consumes the vendored tsmi artifacts (fixtures/bundles) through
// the same loader and asserts the same enrichment contract on golden
// varbinds.

#[test]
fn vendored_bundle_translates_and_resolves() {
    let bundle = load(vendored_bundles());
    let module_names: Vec<&str> = bundle.modules().keys().map(String::as_str).collect();
    assert_eq!(
        module_names,
        vec!["IF-MIB", "IPV6-TC", "SNMPv2-MIB", "TEST-E2E-MIB"]
    );

    assert_eq!(
        bundle.translate("IF-MIB::ifDescr").unwrap(),
        "1.3.6.1.2.1.2.2.1.2"
    );
    assert_eq!(
        bundle.translate("IF-MIB::ifOperStatus.2").unwrap(),
        "1.3.6.1.2.1.2.2.1.8.2"
    );
    assert_eq!(
        bundle.translate("1.3.6.1.6.3.1.1.5.3").unwrap(),
        "IF-MIB::linkDown"
    );
    assert_eq!(
        bundle.translate("1.3.6.1.2.1.2.2.1.2.1").unwrap(),
        "IF-MIB::ifDescr.1"
    );

    let link_down = bundle.resolve_node("IF-MIB", "linkDown").unwrap();
    assert_eq!(link_down.object_type, "NOTIFICATION-TYPE");
    assert_eq!(
        link_down.members.as_ref().map(|members| members
            .iter()
            .map(MibMemberRef::symbolic)
            .collect::<Vec<_>>()),
        Some(vec![
            "IF-MIB::ifIndex".to_string(),
            "IF-MIB::ifAdminStatus".to_string(),
            "IF-MIB::ifOperStatus".to_string(),
        ])
    );
}

#[test]
fn vendored_bundle_renders_enums() {
    // Enum rendering against the vendored IF-MIB. The vendored bundles carry
    // no BITS/UNITS objects, so those render paths are exercised separately
    // against the tsmi-compiled TEST-E2E-MIB fixture
    // (`vendored_bundle_renders_bits_and_units`).
    let bundle = load(vendored_bundles());
    let enriched = enrich_varbinds(
        Some(&bundle),
        vec![
            vb(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 8, 1], SnmpValue::Integer(1)),
            vb(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 8, 2], SnmpValue::Integer(2)),
            vb(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 7, 1], SnmpValue::Integer(1)),
            vb(
                &[1, 3, 6, 1, 2, 1, 1, 1, 0],
                SnmpValue::OctetString(b"Linux test host".to_vec()),
            ),
            vb(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 7], SnmpValue::Integer(7)),
        ],
    );

    // ifOperStatus.1 == up(1); ifOperStatus.2 == down(2).
    assert_eq!(
        enriched[0].display_name.as_deref(),
        Some("IF-MIB::ifOperStatus.1")
    );
    assert_eq!(enriched[0].display_value.as_deref(), Some("up(1)"));
    assert_eq!(enriched[0].enum_label.as_deref(), Some("up"));
    assert_eq!(enriched[1].display_value.as_deref(), Some("down(2)"));
    assert_eq!(enriched[1].enum_label.as_deref(), Some("down"));
    // ifAdminStatus.1 == up(1) (the second enum object in IF-MIB).
    assert_eq!(
        enriched[2].display_name.as_deref(),
        Some("IF-MIB::ifAdminStatus.1")
    );
    assert_eq!(enriched[2].display_value.as_deref(), Some("up(1)"));
    // sysDescr.0 stays a raw octet string; unknown index keeps raw integer.
    assert_eq!(
        enriched[3].display_name.as_deref(),
        Some("SNMPv2-MIB::sysDescr.0")
    );
    assert_eq!(
        enriched[3].display_value.as_deref(),
        Some("Linux test host")
    );
    assert_eq!(
        enriched[4].display_name.as_deref(),
        Some("IF-MIB::ifIndex.7")
    );
    assert_eq!(enriched[4].display_value.as_deref(), Some("7"));
}

#[test]
fn vendored_bundle_renders_bits_and_units() {
    // The tsmi-compiled TEST-E2E-MIB fixture (fixtures/bundles/SOURCE.md)
    // carries the BITS and UNITS objects the other vendored modules lack —
    // the same golden varbinds the reference's test_mib_tsmi_e2e.py asserts.
    let bundle = load(vendored_bundles());
    let enriched = enrich_varbinds(
        Some(&bundle),
        vec![
            vb(&[1, 3, 6, 1, 4, 1, 99999, 1, 0], SnmpValue::Integer(1)),
            vb(&[1, 3, 6, 1, 4, 1, 99999, 2, 0], SnmpValue::Integer(7)),
            vb(
                &[1, 3, 6, 1, 4, 1, 99999, 3, 0],
                SnmpValue::OctetString(vec![0x80]),
            ),
        ],
    );

    assert_eq!(
        enriched[0].display_name.as_deref(),
        Some("TEST-E2E-MIB::status.0")
    );
    assert_eq!(enriched[0].display_value.as_deref(), Some("up(1)"));
    assert_eq!(enriched[0].enum_label.as_deref(), Some("up"));
    assert_eq!(enriched[1].display_value.as_deref(), Some("7"));
    assert_eq!(enriched[1].units.as_deref(), Some("bits/second"));
    assert_eq!(enriched[2].display_value.as_deref(), Some("red(0)"));
}

#[test]
fn vendored_bundle_lookup_metadata() {
    let bundle = load(vendored_bundles());

    let metadata = bundle.lookup_metadata(&oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 8, 0]));
    let metadata = metadata.expect("ifOperStatus resolves");
    assert_eq!(metadata.syntax.as_deref(), Some("INTEGER"));
    assert!(metadata.enums.is_some());
    assert_eq!(metadata.units, None);

    // Ipv6Address textual convention resolves through the imports graph.
    let ipv6 = bundle.resolve_type("IF-MIB", "Ipv6Address");
    // IF-MIB does not import IPV6-TC; SNMPv2-MIB does not either.
    assert!(ipv6.is_none());
    assert!(bundle.resolve_type("IPV6-TC", "Ipv6Address").is_some());
}

// ── manager wiring (test_runtime_manager.py bundle tests) ───────────────────

/// The reference's FakeDispatcher object table (test_runtime_manager.py:79–85).
fn table_objects() -> Vec<(Oid, SnmpValue)> {
    vec![
        (
            oid(&[1, 3, 6, 1, 2, 1, 1, 3, 0]),
            SnmpValue::TimeTicks(12345),
        ),
        (
            oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 1]),
            SnmpValue::OctetString(b"1".to_vec()),
        ),
        (
            oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 2]),
            SnmpValue::OctetString(b"2".to_vec()),
        ),
        (
            oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1]),
            SnmpValue::OctetString(b"eth0".to_vec()),
        ),
        (
            oid(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 2]),
            SnmpValue::OctetString(b"eth1".to_vec()),
        ),
    ]
}

/// A v2c manager connected to a loopback agent and a loaded IF-MIB bundle.
async fn manager_with_bundle(port: u16, bundle: &MibBundle) -> trishul_snmp::manager::Manager {
    trishul_snmp::manager::Manager::connect_v2c(
        trishul_snmp::security::community::CommunityConfig {
            host: "127.0.0.1".to_string(),
            port,
            community: "public".to_string(),
            bundle: Some(std::sync::Arc::new(bundle.clone())),
            timeout: std::time::Duration::from_millis(300),
            retries: 0,
            ..Default::default()
        },
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn manager_get_resolves_symbolic_targets_and_enriches_with_bundle() {
    use common::agent::{FakeAgent, object_logic};
    use trishul_snmp::types::varbind::ErrorStatus;

    // Port of test_runtime_manager.py:test_v2c_manager_get_and_symbolic_translation.
    let (agent, port) = FakeAgent::spawn(object_logic(table_objects(), false)).await;
    let tmp = TempDir::new("manager-get");
    write_json(&tmp.path().join("IF-MIB.json"), &if_mib_payload(true));
    let bundle = load(tmp.path().join("IF-MIB.json"));
    let manager = manager_with_bundle(port, &bundle).await;

    let response = manager.get(vec!["IF-MIB::ifDescr.1"]).await.unwrap();
    assert_eq!(response.error_status, ErrorStatus::NoError);
    assert_eq!(
        response.varbinds[0].display_name.as_deref(),
        Some("IF-MIB::ifDescr.1")
    );
    assert_eq!(response.varbinds[0].display_value.as_deref(), Some("eth0"));
    agent.stop();
}

#[tokio::test]
async fn manager_walk_and_bulkwalk_resolve_symbolic_root_and_enrich() {
    use common::agent::{FakeAgent, object_logic};
    use trishul_snmp::manager::walk::WalkOptions;

    // Port of test_runtime_manager.py:test_v2c_manager_get_bulk_and_walk and
    // test_v2c_manager_get_next_and_walk_variants (the GETNEXT walk and
    // bulkwalk legs; GETBULK batch-fill counts are Phase-2 behavior covered by
    // the walk suite, so the bundle assertions here ride on the walk results).
    let (agent, port) = FakeAgent::spawn(object_logic(table_objects(), false)).await;
    let tmp = TempDir::new("manager-walk");
    write_json(&tmp.path().join("IF-MIB.json"), &if_mib_payload(true));
    let bundle = load(tmp.path().join("IF-MIB.json"));
    let manager = manager_with_bundle(port, &bundle).await;

    let next_walked = manager
        .walk(
            "IF-MIB::ifTable",
            WalkOptions {
                bulk: false,
                max_repetitions: 10,
            },
        )
        .await
        .unwrap();
    let bulk_walked = manager
        .bulkwalk(
            "IF-MIB::ifTable",
            WalkOptions {
                bulk: true,
                max_repetitions: 10,
            },
        )
        .await
        .unwrap();

    let expected = vec![
        "IF-MIB::ifIndex.1",
        "IF-MIB::ifIndex.2",
        "IF-MIB::ifDescr.1",
        "IF-MIB::ifDescr.2",
    ];
    assert_eq!(
        next_walked
            .iter()
            .map(|vb| vb.display_name.as_deref().unwrap())
            .collect::<Vec<_>>(),
        expected
    );
    assert_eq!(
        bulk_walked
            .iter()
            .map(|vb| vb.display_name.as_deref().unwrap())
            .collect::<Vec<_>>(),
        expected
    );
    agent.stop();
}
