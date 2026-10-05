//! Serde types for the compiled-JSON bundle format (schema 1.1)
//! (← mib/models.py + registry.py:305–587)
//!
//! The compiled-JSON format is the tsmi/trishul-smi contract: a module JSON
//! file carrying `module`/`language`/`imports`/`objects`/`notifications`/
//! `types`/`module_metadata`, plus the optional `manifest.json` and
//! `oid_index.json` sidecars (loader.rs). The reference's `isinstance`
//! normalization (registry.py:305–587) collapses into typed `Deserialize` —
//! a wrong field type fails serde and becomes a [`BundleError`]. The checks
//! that encode policy rather than shape stay explicit: the `schema_version`
//! gate, the producer check, the `oid_path`/`oid` consistency rule, and the
//! required non-empty string fields.
//!
//! Field-level leniency mirrors registry.py: `language`/`producer_version`/
//! `generated_at`/`nodetype` are coerced to strings when present (non-strings
//! become `None`/the default), while `syntax`/`max_access`/`status`/… are
//! strict (a present non-string is an error).

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

use crate::error::BundleError;
use crate::types::oid::Oid;

/// The producer that generates supported bundles (registry.py:19).
pub(crate) const SUPPORTED_PRODUCER: &str = "trishul-smi";
/// The newest accepted schema version (registry.py:20).
pub(crate) const SUPPORTED_SCHEMA_VERSION: &str = "1.1";

/// Structured reference to another retained symbol (models.py:12–21).
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct MibMemberRef {
    /// The referenced module name.
    pub module: String,
    /// The referenced symbol within `module`.
    pub object: String,
}

impl MibMemberRef {
    /// `MODULE::symbol` form (models.py:19–21).
    #[must_use]
    pub fn symbolic(&self) -> String {
        format!("{}::{}", self.module, self.object)
    }
}

/// Normalized object or notification record (models.py:24–47).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MibNode {
    /// The owning module name.
    pub module: String,
    /// The symbol name.
    pub name: String,
    /// The object's numeric OID.
    pub oid: Oid,
    /// Producer class label (`objecttype`, `moduleidentity`, `objectidentifier`,
    /// `notificationtype`, …).
    pub class_name: String,
    /// `OBJECT-TYPE`, `MODULE-IDENTITY`, `OBJECT IDENTIFIER`,
    /// `NOTIFICATION-TYPE`, ….
    pub object_type: String,
    /// `scalar`, `table`, `column`, `notification`, … (absent for objects with
    /// no declared nodetype; `"notification"` for notifications).
    pub nodetype: Option<String>,
    /// SYNTAX name when the object declared one.
    pub syntax: Option<String>,
    /// MAX-ACCESS clause.
    pub max_access: Option<String>,
    /// STATUS clause.
    pub status: Option<String>,
    /// INDEX clause columns.
    pub index: Option<Vec<String>>,
    /// AUGMENTS clause.
    pub augments: Option<String>,
    /// DESCRIPTION text.
    pub description: Option<String>,
    /// NOTIFICATION-TYPE OBJECTS (member) references.
    pub members: Option<Vec<MibMemberRef>>,
    /// Constraint object (`{"kind": "enum"|"bits"|"range"|"size", "data": …}`),
    /// kept as raw JSON to mirror the reference's `Mapping[str, Any]`.
    pub constraints: Option<serde_json::Value>,
    /// Inline label→number map for INTEGER/BITS constraints (v0.5.2 additive
    /// metadata).
    pub enums: Option<BTreeMap<String, i64>>,
    /// SMIv2 UNITS clause.
    pub units: Option<String>,
}

impl MibNode {
    /// `MODULE::name` form (models.py:45–47).
    #[must_use]
    pub fn symbolic(&self) -> String {
        format!("{}::{}", self.module, self.name)
    }
}

/// Normalized textual-convention record (models.py:50–61).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MibTypeRecord {
    /// The owning module name.
    pub module: String,
    /// The textual-convention name.
    pub name: String,
    /// Producer class label (`textualconvention`).
    pub class_name: String,
    /// The base SMI type (`Integer32`, `OctetString`, `BITS`, …).
    pub base_type: Option<String>,
    /// The DISPLAY-HINT clause.
    pub display_hint: Option<String>,
    /// STATUS clause.
    pub status: Option<String>,
    /// Constraint object (same shape as [`MibNode::constraints`]).
    pub constraints: Option<serde_json::Value>,
}

/// Normalized module payload (models.py:63–80).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MibModuleRecord {
    /// The module name.
    pub module: String,
    /// `SMIv2`, … (coerced from the payload's `language` field).
    pub language: Option<String>,
    /// The producing tool (`trishul-smi`).
    pub generated_by: String,
    /// ISO timestamp of generation.
    pub generated_at: Option<String>,
    /// Schema version, validated by the `≤ 1.1` gate.
    pub schema_version: Option<String>,
    /// Producer tool version.
    pub producer_version: Option<String>,
    /// Import graph: imported module → imported symbol names.
    pub imports: BTreeMap<String, Vec<String>>,
    /// Object nodes keyed by symbol name.
    pub objects: BTreeMap<String, MibNode>,
    /// Notification nodes keyed by symbol name.
    pub notifications: BTreeMap<String, MibNode>,
    /// Textual-convention records keyed by name.
    pub types: BTreeMap<String, MibTypeRecord>,
    /// Free-form module metadata object (`lastupdated`, `revisions`, …).
    pub module_metadata: serde_json::Value,
}

impl MibModuleRecord {
    /// Objects and notifications in one iterator (models.py:79–80).
    pub fn iter_nodes(&self) -> impl Iterator<Item = &MibNode> {
        self.objects.values().chain(self.notifications.values())
    }
}

/// Raw node fields as they appear in a module JSON `objects`/`notifications`
/// map (registry.py:331–407).
#[derive(Debug, Deserialize)]
struct RawNode {
    #[serde(default)]
    oid_path: Option<Vec<u32>>,
    #[serde(default)]
    oid: Option<String>,
    object_type: String,
    class: String,
    #[serde(default)]
    nodetype: Option<serde_json::Value>,
    #[serde(default)]
    syntax: Option<String>,
    #[serde(default)]
    max_access: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    index: Option<Vec<String>>,
    #[serde(default)]
    augments: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    members: Option<Vec<MibMemberRef>>,
    #[serde(default)]
    constraints: Option<serde_json::Value>,
    #[serde(default)]
    enums: Option<BTreeMap<String, i64>>,
    #[serde(default)]
    units: Option<String>,
}

/// Raw textual-convention fields as they appear in a module JSON `types` map
/// (registry.py:409–442).
#[derive(Debug, Deserialize)]
struct RawType {
    class: String,
    #[serde(default)]
    base_type: Option<String>,
    #[serde(default)]
    display_hint: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    constraints: Option<serde_json::Value>,
}

/// Raw module payload as it appears in a module JSON file
/// (registry.py:541–587). The collection fields stay raw so each normalize
/// function owns its validation; `None` ≡ absent (≡ `{}` in Python).
#[derive(Debug, Deserialize)]
struct RawModule {
    module: String,
    #[serde(default)]
    language: Option<serde_json::Value>,
    generated_by: String,
    #[serde(default)]
    generated_at: Option<serde_json::Value>,
    #[serde(default)]
    schema_version: Option<serde_json::Value>,
    #[serde(default)]
    producer_version: Option<serde_json::Value>,
    #[serde(default)]
    imports: Option<serde_json::Value>,
    #[serde(default)]
    objects: Option<serde_json::Value>,
    #[serde(default)]
    notifications: Option<serde_json::Value>,
    #[serde(default)]
    types: Option<serde_json::Value>,
    #[serde(default)]
    module_metadata: Option<serde_json::Value>,
}

/// Builds a `BundleError::Validation` for `path` (← `errors.py`'s
/// `BundleValidationError` message-plus-path shape).
fn validation(path: &Path, message: impl Into<String>) -> BundleError {
    BundleError::Validation {
        path: path.display().to_string(),
        message: message.into(),
    }
}

/// Parses a dotted numeric version into a comparable tuple (registry.py:23–28).
fn schema_version_key(value: &str) -> Option<Vec<u32>> {
    if value.is_empty() {
        return None;
    }
    let mut parts = Vec::new();
    for part in value.split('.') {
        if part.is_empty() || !part.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        parts.push(part.parse().ok()?);
    }
    Some(parts)
}

/// Validates an artifact's `schema_version` against the supported maximum
/// (registry.py:31–70). Returns the normalized version string, or `None` when
/// the artifact has no `schema_version`.
pub fn validate_schema_version(
    schema_version: Option<&serde_json::Value>,
    path: &Path,
    producer_version: Option<&str>,
) -> Result<Option<String>, BundleError> {
    let Some(value) = schema_version else {
        return Ok(None);
    };
    let Some(text) = value.as_str() else {
        return Err(validation(
            path,
            "schema_version must be a dotted numeric string",
        ));
    };
    let normalized = text.trim();
    if normalized.is_empty() {
        return Err(validation(
            path,
            "schema_version must be a dotted numeric string",
        ));
    }
    let version_key = schema_version_key(normalized).ok_or_else(|| {
        validation(
            path,
            format!("schema_version {text:?} is not a valid dotted numeric version"),
        )
    })?;
    let supported = schema_version_key(SUPPORTED_SCHEMA_VERSION).expect("fixed version");
    if version_key <= supported {
        return Ok(Some(normalized.to_string()));
    }
    let producer_note = producer_version
        .map(|p| format!(" (producer_version {p})"))
        .unwrap_or_default();
    Err(validation(
        path,
        format!(
            "schema_version {text:?} is newer than the supported maximum {SUPPORTED_SCHEMA_VERSION:?}; \
             the bundle was produced by a newer incompatible trishul-smi{producer_note}"
        ),
    ))
}

/// Validates the producer of a normalized module record (registry.py:305–311).
fn validate_module_record(record: &MibModuleRecord, path: &Path) -> Result<(), BundleError> {
    if record.generated_by != SUPPORTED_PRODUCER {
        return Err(validation(
            path,
            format!("Unsupported JSON producer {:?}", record.generated_by),
        ));
    }
    Ok(())
}

/// Normalizes a module's import graph (registry.py:314–328). The isinstance
/// checks collapse into serde; only the empty-string module-name guard stays
/// explicit.
fn normalize_imports(
    raw_imports: Option<&serde_json::Value>,
    path: &Path,
) -> Result<BTreeMap<String, Vec<String>>, BundleError> {
    let Some(raw_imports) = raw_imports else {
        return Ok(BTreeMap::new());
    };
    if !raw_imports.is_object() {
        return Err(validation(path, "Module imports must be an object"));
    }
    let imports: BTreeMap<String, Vec<String>> = serde_json::from_value(raw_imports.clone())
        .map_err(|e| validation(path, format!("Invalid module imports: {e}")))?;
    Ok(imports)
}

/// Resolves a node's OID from its `oid_path` and/or `oid` fields
/// (registry.py:445–468).
fn normalize_node_oid(
    oid_path: Option<Vec<u32>>,
    oid_value: Option<&str>,
    name: &str,
    path: &Path,
) -> Result<Oid, BundleError> {
    if let Some(arcs) = oid_path {
        let oid = Oid::from_arcs(&arcs).map_err(|e| {
            validation(
                path,
                format!("Node {name:?} has an invalid oid_path: {}", e.0),
            )
        })?;
        if let Some(text) = oid_value
            && let Ok(parsed) = Oid::parse(text)
            && parsed != oid
        {
            return Err(validation(
                path,
                format!("Node {name:?} has inconsistent oid and oid_path values"),
            ));
        }
        return Ok(oid);
    }
    if let Some(text) = oid_value {
        return Oid::parse(text)
            .map_err(|e| validation(path, format!("Node {name:?} has an invalid oid: {}", e.0)));
    }
    Err(validation(
        path,
        format!("Node {name:?} is missing both oid_path and oid"),
    ))
}

/// Requires a non-empty string field (registry.py:479–487).
fn require_string(value: &str, field: &str, name: &str, path: &Path) -> Result<(), BundleError> {
    if value.is_empty() {
        return Err(validation(
            path,
            format!("Node {name:?} is missing required string field {field:?}"),
        ));
    }
    Ok(())
}

/// Normalizes one module's object or notification map (registry.py:331–407).
pub fn normalize_node_map(
    raw_nodes: Option<&serde_json::Value>,
    module_name: &str,
    path: &Path,
    default_nodetype: Option<&str>,
) -> Result<BTreeMap<String, MibNode>, BundleError> {
    let Some(raw_nodes) = raw_nodes else {
        return Ok(BTreeMap::new());
    };
    if !raw_nodes.is_object() {
        return Err(validation(path, "Node collections must be objects"));
    }
    let raw: BTreeMap<String, RawNode> = serde_json::from_value(raw_nodes.clone())
        .map_err(|e| validation(path, format!("Invalid node collection: {e}")))?;

    let mut normalized = BTreeMap::new();
    for (name, node) in raw {
        require_string(&node.object_type, "object_type", &name, path)?;
        require_string(&node.class, "class", &name, path)?;
        if let Some(members) = &node.members
            && members
                .iter()
                .any(|member| member.module.is_empty() || member.object.is_empty())
        {
            return Err(validation(
                path,
                format!("Node {name:?} members must contain string 'module' and 'object' fields"),
            ));
        }
        if let Some(constraints) = &node.constraints
            && !constraints.is_object()
        {
            return Err(validation(
                path,
                format!("Node {name:?} constraints must be an object"),
            ));
        }
        let oid = normalize_node_oid(node.oid_path, node.oid.as_deref(), &name, path)?;
        normalized.insert(
            name.clone(),
            MibNode {
                module: module_name.to_string(),
                name,
                oid,
                class_name: node.class,
                object_type: node.object_type,
                nodetype: node
                    .nodetype
                    .and_then(|v| v.as_str().map(str::to_string))
                    .or_else(|| default_nodetype.map(str::to_string)),
                syntax: node.syntax,
                max_access: node.max_access,
                status: node.status,
                index: node.index,
                augments: node.augments,
                description: node.description,
                members: node.members,
                constraints: node.constraints,
                enums: node.enums,
                units: node.units,
            },
        );
    }
    Ok(normalized)
}

/// Normalizes one module's textual-convention map (registry.py:409–442).
pub fn normalize_type_map(
    raw_types: Option<&serde_json::Value>,
    module_name: &str,
    path: &Path,
) -> Result<BTreeMap<String, MibTypeRecord>, BundleError> {
    let Some(raw_types) = raw_types else {
        return Ok(BTreeMap::new());
    };
    if !raw_types.is_object() {
        return Err(validation(path, "Type collections must be objects"));
    }
    let raw: BTreeMap<String, RawType> = serde_json::from_value(raw_types.clone())
        .map_err(|e| validation(path, format!("Invalid type collection: {e}")))?;

    let mut normalized = BTreeMap::new();
    for (name, record) in raw {
        require_string(&record.class, "class", &name, path)?;
        if let Some(constraints) = &record.constraints
            && !constraints.is_object()
        {
            return Err(validation(
                path,
                format!("Type {name:?} constraints must be an object"),
            ));
        }
        normalized.insert(
            name.clone(),
            MibTypeRecord {
                module: module_name.to_string(),
                name,
                class_name: record.class,
                base_type: record.base_type,
                display_hint: record.display_hint,
                status: record.status,
                constraints: record.constraints,
            },
        );
    }
    Ok(normalized)
}

/// Normalizes the free-form module metadata object (registry.py:531–538).
pub fn normalize_module_metadata(
    raw_metadata: Option<&serde_json::Value>,
    path: &Path,
) -> Result<serde_json::Value, BundleError> {
    match raw_metadata {
        None => Ok(serde_json::Value::Object(serde_json::Map::new())),
        Some(value) if value.is_object() => Ok(value.clone()),
        Some(_) => Err(validation(path, "Module metadata must be an object")),
    }
}

/// Validates and normalizes a raw module payload (registry.py:541–587).
pub fn normalize_module_payload(
    payload: &serde_json::Value,
    path: &Path,
) -> Result<MibModuleRecord, BundleError> {
    if !payload.is_object() {
        return Err(validation(path, "Module JSON must be an object"));
    }
    let raw: RawModule = serde_json::from_value(payload.clone())
        .map_err(|e| validation(path, format!("Invalid module JSON: {e}")))?;
    if raw.module.is_empty() {
        return Err(validation(
            path,
            "Module JSON is missing a valid 'module' field",
        ));
    }
    if raw.generated_by.is_empty() {
        return Err(validation(
            path,
            "Module JSON is missing a valid 'generated_by' field",
        ));
    }
    let producer_version = raw
        .producer_version
        .and_then(|v| v.as_str().map(str::to_string));
    let schema_version = validate_schema_version(
        raw.schema_version.as_ref(),
        path,
        producer_version.as_deref(),
    )?;
    let module_metadata = normalize_module_metadata(raw.module_metadata.as_ref(), path)?;
    let objects = normalize_node_map(raw.objects.as_ref(), &raw.module, path, None)?;
    let notifications = normalize_node_map(
        raw.notifications.as_ref(),
        &raw.module,
        path,
        Some("notification"),
    )?;
    let types = normalize_type_map(raw.types.as_ref(), &raw.module, path)?;

    let record = MibModuleRecord {
        language: raw.language.and_then(|v| v.as_str().map(str::to_string)),
        generated_at: raw
            .generated_at
            .and_then(|v| v.as_str().map(str::to_string)),
        module: raw.module,
        generated_by: raw.generated_by,
        schema_version,
        producer_version,
        imports: normalize_imports(raw.imports.as_ref(), path)?,
        objects,
        notifications,
        types,
        module_metadata,
    };
    validate_module_record(&record, path)?;
    Ok(record)
}

#[cfg(test)]
pub(crate) mod tests {
    use serde_json::{Value, json};

    /// The `_base_module` payload helper shared by the in-module test suites
    /// (test_bundle_loading.py:_base_module).
    pub(crate) fn test_base_module(module: &str, imports: &Value) -> Value {
        json!({
            "module": module,
            "language": "SMIv2",
            "generated_by": "trishul-smi",
            "generated_at": "2026-05-06T12:00:00Z",
            "imports": imports,
            "objects": {},
            "types": {},
            "notifications": {},
            "module_metadata": {"lastupdated": null, "revisions": []},
        })
    }
}
