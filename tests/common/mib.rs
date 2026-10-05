//! Shared MIB bundle test fixtures (← tests/_bundle_fixtures.py and the
//! per-suite payload builders in test_bundle_loading.py, test_mib_internals.py,
//! test_rendering.py, test_bundle_iteration.py, and the NOTIF-MIB payloads of
//! test_notification_to_dict.py / test_notification_listener.py).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};

/// A unique scratch directory under the system temp dir, removed on drop.
pub struct TempDir {
    path: PathBuf,
}

static DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

impl TempDir {
    /// Creates a fresh scratch directory (unique per call, parallel-test safe).
    #[must_use]
    pub fn new(tag: &str) -> Self {
        let counter = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("tsnmp-mib-{tag}-{}-{counter}", std::process::id()));
        fs::create_dir_all(&path).expect("create scratch bundle directory");
        Self { path }
    }

    /// The scratch directory path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Writes a pretty-printed JSON payload to `path` (`_write_json`).
pub fn write_json(path: &Path, payload: &Value) {
    fs::write(path, serde_json::to_string_pretty(payload).unwrap()).unwrap();
}

/// The vendored `fixtures/bundles` directory (crate root).
pub fn vendored_bundles() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/bundles")
}

/// The base module payload shared by the test suites
/// (test_bundle_loading.py:_base_module; no `schema_version` so the
/// missing-schema path is exercisable).
pub fn base_module(module: &str, imports: Option<&Value>) -> Value {
    json!({
        "module": module,
        "language": "SMIv2",
        "generated_by": "trishul-smi",
        "generated_at": "2026-05-06T12:00:00Z",
        "imports": imports.cloned().unwrap_or_else(|| json!({})),
        "objects": {},
        "types": {},
        "notifications": {},
        "module_metadata": {"lastupdated": null, "revisions": []},
    })
}

/// The IF-MIB payload (test_bundle_loading.py:_if_mib_payload).
pub fn if_mib_payload(include_imports: bool) -> Value {
    let imports = if include_imports {
        Some(json!({"SNMPv2-TC": ["DisplayString"]}))
    } else {
        None
    };
    let mut payload = base_module("IF-MIB", imports.as_ref());
    payload["objects"] = json!({
        "ifTable": {
            "oid": "1.3.6.1.2.1.2.2",
            "oid_path": [1, 3, 6, 1, 2, 1, 2, 2],
            "object_type": "OBJECT-TYPE",
            "class": "objecttype",
            "nodetype": "table",
            "syntax": "SEQUENCE OF IfEntry",
            "max_access": "not-accessible",
            "status": "current",
        },
        "ifDescr": {
            "oid": "1.3.6.1.2.1.2.2.1.2",
            "oid_path": [1, 3, 6, 1, 2, 1, 2, 2, 1, 2],
            "object_type": "OBJECT-TYPE",
            "class": "objecttype",
            "nodetype": "column",
            "syntax": "DisplayString",
            "max_access": "read-only",
            "status": "current",
            "index": ["ifIndex"],
        },
        "ifIndex": {
            "oid": "1.3.6.1.2.1.2.2.1.1",
            "oid_path": [1, 3, 6, 1, 2, 1, 2, 2, 1, 1],
            "object_type": "OBJECT-TYPE",
            "class": "objecttype",
            "nodetype": "column",
            "syntax": "InterfaceIndex",
            "max_access": "read-only",
            "status": "current",
        }
    });
    payload["types"] = json!({
        "InterfaceIndex": {
            "class": "textualconvention",
            "base_type": "Integer32",
            "display_hint": "d",
            "status": "current",
        }
    });
    payload
}

/// The SNMPv2-TC payload (test_bundle_loading.py:_snmpv2_tc_payload).
pub fn snmpv2_tc_payload() -> Value {
    let mut payload = base_module("SNMPv2-TC", None);
    payload["types"] = json!({
        "DisplayString": {
            "class": "textualconvention",
            "base_type": "OctetString",
            "display_hint": "255a",
            "status": "current",
        }
    });
    payload
}

/// The ENUM-TC payload (test_mib_internals.py:_enum_tc_payload).
pub fn enum_tc_payload() -> Value {
    let mut payload = base_module("ENUM-TC", None);
    payload["types"] = json!({
        "TruthValue": {
            "class": "textualconvention",
            "base_type": "Integer32",
            "status": "current",
            "constraints": {"kind": "enum", "data": [["up", 1], ["down", 2]]},
        }
    });
    payload
}

/// The APP-MIB payload (test_mib_internals.py:_app_payload).
pub fn app_payload(
    syntax: Option<&str>,
    imports: Option<&Value>,
    node_constraints: Option<&Value>,
    include_local_type: bool,
) -> Value {
    let imports = imports
        .cloned()
        .unwrap_or_else(|| json!({"ENUM-TC": ["TruthValue"]}));
    let mut payload = base_module("APP-MIB", Some(&imports));
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
        status_node["syntax"] = Value::String(syntax.to_string());
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

/// The TEST-TC payload (test_rendering.py:_test_tc_payload).
pub fn test_tc_payload() -> Value {
    let mut payload = base_module("TEST-TC", None);
    payload["types"] = json!({
        "TruthValue": {
            "class": "textualconvention",
            "base_type": "Integer32",
            "display_hint": "d",
            "status": "current",
            "constraints": {"kind": "enum", "data": [["up", 1], ["down", 2]]},
        }
    });
    payload
}

/// The TEST-APP-MIB payload (test_rendering.py:_test_app_payload).
pub fn test_app_payload() -> Value {
    let mut payload = base_module("TEST-APP-MIB", Some(&json!({"TEST-TC": ["TruthValue"]})));
    payload["objects"] = json!({
        "adminStatus": {
            "oid": "1.3.6.1.4.1.99999.1",
            "oid_path": [1, 3, 6, 1, 4, 1, 99999, 1],
            "object_type": "OBJECT-TYPE",
            "class": "objecttype",
            "nodetype": "scalar",
            "syntax": "TruthValue",
            "max_access": "read-only",
            "status": "current",
        },
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
        "peerReference": {
            "oid": "1.3.6.1.4.1.99999.3",
            "oid_path": [1, 3, 6, 1, 4, 1, 99999, 3],
            "object_type": "OBJECT-TYPE",
            "class": "objecttype",
            "nodetype": "scalar",
            "syntax": "OBJECT IDENTIFIER",
            "max_access": "read-only",
            "status": "current",
        },
    });
    payload
}

/// The NOTIF-MIB payload (test_notification_to_dict.py:_notification_payload).
pub fn notif_mib_payload() -> Value {
    let mut payload = base_module("NOTIF-MIB", None);
    payload["objects"] = json!({
        "ifIndex": {
            "oid": "1.3.6.1.2.1.2.2.1.1",
            "oid_path": [1, 3, 6, 1, 2, 1, 2, 2, 1, 1],
            "object_type": "OBJECT-TYPE",
            "class": "objecttype",
            "nodetype": "column",
            "syntax": "Integer32",
            "max_access": "read-only",
            "status": "current",
        }
    });
    payload["notifications"] = json!({
        "linkDown": {
            "oid": "1.3.6.1.6.3.1.1.5.3",
            "oid_path": [1, 3, 6, 1, 6, 3, 1, 1, 5, 3],
            "object_type": "NOTIFICATION-TYPE",
            "class": "notificationtype",
            "status": "current",
            "description": "A linkDown notification.",
            "members": [{"module": "NOTIF-MIB", "object": "ifIndex"}],
        }
    });
    payload
}

/// Writes a two-module bundle where a scalar base and an exact `.0` alias
/// coexist (`write_scalar_instance_alias_bundle`).
pub fn write_scalar_instance_alias_bundle(dir: &Path) {
    let mut snmpv2_mib = base_module("SNMPv2-MIB", None);
    snmpv2_mib["objects"] = json!({
        "system": {
            "oid": "1.3.6.1.2.1.1",
            "oid_path": [1, 3, 6, 1, 2, 1, 1],
            "object_type": "OBJECT IDENTIFIER",
            "class": "objectidentifier",
            "syntax": null,
            "max_access": null,
            "status": null,
            "index": null,
            "augments": null,
            "description": null,
        },
        "sysUpTime": {
            "oid": "1.3.6.1.2.1.1.3",
            "oid_path": [1, 3, 6, 1, 2, 1, 1, 3],
            "object_type": "OBJECT-TYPE",
            "class": "objecttype",
            "nodetype": "scalar",
            "syntax": "TimeTicks",
            "max_access": "read-only",
            "status": "current",
            "index": null,
            "augments": null,
            "description": "Time since the network management subsystem was last reset.",
        },
    });

    let mut disman = base_module(
        "DISMAN-EXPRESSION-MIB",
        Some(&json!({"SNMPv2-MIB": ["sysUpTime"]})),
    );
    disman["objects"] = json!({
        "sysUpTimeInstance": {
            "oid": "1.3.6.1.2.1.1.3.0",
            "oid_path": [1, 3, 6, 1, 2, 1, 1, 3, 0],
            "object_type": "OBJECT IDENTIFIER",
            "class": "objectidentifier",
            "syntax": null,
            "max_access": null,
            "status": null,
            "index": null,
            "augments": null,
            "description": null,
        }
    });

    write_json(&dir.join("SNMPv2-MIB.json"), &snmpv2_mib);
    write_json(&dir.join("DISMAN-EXPRESSION-MIB.json"), &disman);
    write_json(
        &dir.join("manifest.json"),
        &json!({
            "schema_version": "1.1",
            "producer_version": "0.4.1",
            "generated_by": "trishul-smi",
            "generated_at": "2026-05-07T12:00:00Z",
            "modules": [
                {"module": "DISMAN-EXPRESSION-MIB", "file": "DISMAN-EXPRESSION-MIB.json"},
                {"module": "SNMPv2-MIB", "file": "SNMPv2-MIB.json"},
            ],
            "sidecars": {"oid_index": "oid_index.json"},
        }),
    );
    write_json(
        &dir.join("oid_index.json"),
        &json!({
            "schema_version": "1.1",
            "producer_version": "0.4.1",
            "generated_by": "trishul-smi",
            "generated_at": "2026-05-07T12:00:00Z",
            "oids": {
                "1.3.6.1.2.1.1.3": {
                    "module": "SNMPv2-MIB",
                    "object": "sysUpTime",
                    "class": "objecttype",
                    "object_type": "OBJECT-TYPE",
                    "nodetype": "scalar",
                },
                "1.3.6.1.2.1.1.3.0": {
                    "module": "DISMAN-EXPRESSION-MIB",
                    "object": "sysUpTimeInstance",
                    "class": "objectidentifier",
                    "object_type": "OBJECT IDENTIFIER",
                },
            },
        }),
    );
}

/// Writes the VALUE-META-MIB payload carrying the v0.5.2 additive value
/// metadata fields (`write_value_metadata_bundle`).
pub fn write_value_metadata_bundle(dir: &Path) {
    let mut module = base_module("VALUE-META-MIB", None);
    module["objects"] = json!({
        "operStatus": {
            "oid": "1.3.6.1.4.1.99999.1",
            "oid_path": [1, 3, 6, 1, 4, 1, 99999, 1],
            "object_type": "OBJECT-TYPE",
            "class": "objecttype",
            "nodetype": "scalar",
            "syntax": "INTEGER",
            "max_access": "read-only",
            "status": "current",
            "index": null,
            "augments": null,
            "description": null,
            "constraints": {"kind": "enum", "data": [["up", 1], ["down", 2], ["testing", 3]]},
            "enums": {"up": 1, "down": 2, "testing": 3},
        },
        "portFlags": {
            "oid": "1.3.6.1.4.1.99999.2",
            "oid_path": [1, 3, 6, 1, 4, 1, 99999, 2],
            "object_type": "OBJECT-TYPE",
            "class": "objecttype",
            "nodetype": "scalar",
            "syntax": "BITS",
            "max_access": "read-only",
            "status": "current",
            "index": null,
            "augments": null,
            "description": null,
            "constraints": {"kind": "bits", "data": [["red", 0], ["green", 1], ["blue", 2]]},
            "enums": {"red": 0, "green": 1, "blue": 2},
        },
        "linkSpeed": {
            "oid": "1.3.6.1.4.1.99999.3",
            "oid_path": [1, 3, 6, 1, 4, 1, 99999, 3],
            "object_type": "OBJECT-TYPE",
            "class": "objecttype",
            "nodetype": "scalar",
            "syntax": "Gauge32",
            "units": "bits/second",
            "max_access": "read-only",
            "status": "current",
            "index": null,
            "augments": null,
            "description": null,
        },
        "payloadSize": {
            "oid": "1.3.6.1.4.1.99999.4",
            "oid_path": [1, 3, 6, 1, 4, 1, 99999, 4],
            "object_type": "OBJECT-TYPE",
            "class": "objecttype",
            "nodetype": "scalar",
            "syntax": "Integer32",
            "max_access": "read-only",
            "status": "current",
            "index": null,
            "augments": null,
            "description": null,
            "constraints": {"kind": "range", "data": [[0, 65507]]},
        },
        "plainCounter": {
            "oid": "1.3.6.1.4.1.99999.5",
            "oid_path": [1, 3, 6, 1, 4, 1, 99999, 5],
            "object_type": "OBJECT-TYPE",
            "class": "objecttype",
            "nodetype": "scalar",
            "syntax": "Counter32",
            "max_access": "read-only",
            "status": "current",
            "index": null,
            "augments": null,
            "description": null,
        },
    });
    write_json(&dir.join("VALUE-META-MIB.json"), &module);
}

/// Writes the two-module iteration/search bundle (test_bundle_iteration.py:
/// `_multi_module_bundle`).
pub fn write_multi_module_bundle(dir: &Path) {
    let mut mib_a = base_module("MIB-A", None);
    mib_a["objects"] = json!({
        "sysDescr": {
            "oid": "1.3.6.1.2.1.1.1",
            "oid_path": [1, 3, 6, 1, 2, 1, 1, 1],
            "object_type": "OBJECT-TYPE",
            "class": "objecttype",
            "nodetype": "scalar",
            "syntax": "DisplayString",
            "max_access": "read-only",
            "status": "current",
            "description": "The system description.",
        },
        "ifIndex": {
            "oid": "1.3.6.1.2.1.2.2.1.1",
            "oid_path": [1, 3, 6, 1, 2, 1, 2, 2, 1, 1],
            "object_type": "OBJECT-TYPE",
            "class": "objecttype",
            "nodetype": "column",
            "syntax": "Integer32",
            "max_access": "read-only",
            "status": "current",
            "description": "Interface index column.",
        },
    });
    mib_a["notifications"] = json!({
        "linkDown": {
            "oid": "1.3.6.1.6.3.1.1.5.3",
            "oid_path": [1, 3, 6, 1, 6, 3, 1, 1, 5, 3],
            "object_type": "NOTIFICATION-TYPE",
            "class": "notificationtype",
            "status": "current",
            "description": "A link down notification.",
        }
    });

    let mut mib_b = base_module("MIB-B", None);
    mib_b["objects"] = json!({
        "sysUpTime": {
            "oid": "1.3.6.1.2.1.1.3",
            "oid_path": [1, 3, 6, 1, 2, 1, 1, 3],
            "object_type": "OBJECT-TYPE",
            "class": "objecttype",
            "nodetype": "scalar",
            "syntax": "TimeTicks",
            "max_access": "read-only",
            "status": "current",
            "description": "System uptime ticks.",
        }
    });
    mib_b["notifications"] = json!({
        "linkUp": {
            "oid": "1.3.6.1.6.3.1.1.5.4",
            "oid_path": [1, 3, 6, 1, 6, 3, 1, 1, 5, 4],
            "object_type": "NOTIFICATION-TYPE",
            "class": "notificationtype",
            "status": "current",
            "description": "A link up event.",
        }
    });

    write_json(&dir.join("MIB-A.json"), &mib_a);
    write_json(&dir.join("MIB-B.json"), &mib_b);
}

/// A `_valid_node`-style object payload for validation tests
/// (test_mib_internals.py:_valid_node).
pub fn valid_node(overrides: &Value) -> Value {
    let mut node = json!({
        "oid": "1.3.6.1.4.1.99999.1",
        "oid_path": [1, 3, 6, 1, 4, 1, 99999, 1],
        "object_type": "OBJECT-TYPE",
        "class": "objecttype",
        "nodetype": "scalar",
        "syntax": "TruthValue",
        "max_access": "read-only",
        "status": "current",
    });
    if let Some(obj) = overrides.as_object() {
        for (key, value) in obj {
            node[key] = value.clone();
        }
    }
    node
}

/// A `_valid_type`-style type payload for validation tests
/// (test_mib_internals.py:_valid_type).
pub fn valid_type(overrides: &Value) -> Value {
    let mut record = json!({
        "class": "textualconvention",
        "base_type": "Integer32",
        "display_hint": "d",
        "status": "current",
    });
    if let Some(obj) = overrides.as_object() {
        for (key, value) in obj {
            record[key] = value.clone();
        }
    }
    record
}

/// An `_enums_node`-style object payload (test_mib_internals.py:_enums_node).
pub fn enums_node(overrides: &Value) -> Value {
    let mut node = valid_node(&json!({}));
    node["enums"] = json!({"up": 1, "down": 2});
    node["units"] = json!("bits/second");
    if let Some(obj) = overrides.as_object() {
        for (key, value) in obj {
            node[key] = value.clone();
        }
    }
    node
}
