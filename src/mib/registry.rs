//! Symbol/OID indexes (← mib/registry.py:149–303)
//!
//! The in-memory indexes built over loaded module records: symbol → OID,
//! node OID → (module, symbol), and the optional sidecar accelerator
//! (`oid_index.json`). `lookup_oid` implements the longest-prefix semantics
//! (registry.py:183–217) and `display_symbolic` the user-facing `.0`-scalar
//! display policy (registry.py:219–236, 280–302).

use std::collections::{BTreeMap, HashMap};

use crate::error::TranslationError;
use crate::mib::model::{MibModuleRecord, MibNode, MibTypeRecord};
use crate::types::oid::Oid;
use crate::types::varbind::OidMatch;

/// Value-rendering metadata for an object owning a binding OID
/// (registry.py:134–147): the ordered label→number mapping for INTEGER/BITS
/// inline constraints, the SMIv2 UNITS clause, and the SYNTAX name. All three
/// are `None` when the source module did not provide them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeValueMetadata {
    /// Label→number map (INTEGER/BITS inline constraints).
    pub enums: Option<BTreeMap<String, i64>>,
    /// SMIv2 UNITS clause.
    pub units: Option<String>,
    /// SYNTAX name.
    pub syntax: Option<String>,
}

/// A sidecar `oid_index.json` entry (registry.py:128–132).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OidIndexEntry {
    /// Module owning the accelerated OID.
    pub module: String,
    /// Symbol within the module.
    pub symbol: String,
}

/// In-memory indexes over loaded MIB modules (registry.py:149–303).
#[derive(Debug)]
pub(crate) struct RegistryInner {
    modules: BTreeMap<String, MibModuleRecord>,
    /// `(module, symbol)` → node OID (objects + notifications).
    symbol_oids: HashMap<(String, String), Oid>,
    /// Node OID → `(module, symbol)` (the reference's `_exact_oid_index`).
    node_oids: BTreeMap<Oid, (String, String)>,
    /// Sidecar accelerator OID → `(module, symbol)` (the reference's
    /// `_oid_index`).
    oid_index: BTreeMap<Oid, OidIndexEntry>,
}

impl RegistryInner {
    /// Builds the indexes over the loaded modules (registry.py:152–169).
    pub(crate) fn new(
        modules: BTreeMap<String, MibModuleRecord>,
        oid_index: BTreeMap<Oid, OidIndexEntry>,
    ) -> Self {
        let mut symbol_oids = HashMap::new();
        let mut node_oids = BTreeMap::new();
        for record in modules.values() {
            for node in record.iter_nodes() {
                symbol_oids.insert((record.module.clone(), node.name.clone()), node.oid.clone());
                node_oids.insert(node.oid.clone(), (record.module.clone(), node.name.clone()));
            }
        }
        Self {
            modules,
            symbol_oids,
            node_oids,
            oid_index,
        }
    }

    /// The loaded module records.
    pub(crate) fn modules(&self) -> &BTreeMap<String, MibModuleRecord> {
        &self.modules
    }

    /// Resolves `MODULE::symbol` to the node's numeric OID
    /// (registry.py:175–181).
    pub(crate) fn resolve_node_oid(
        &self,
        module: &str,
        symbol: &str,
    ) -> Result<Oid, TranslationError> {
        self.symbol_oids
            .get(&(module.to_string(), symbol.to_string()))
            .cloned()
            .ok_or_else(|| {
                TranslationError::UnknownSymbol(format!(
                    "Unknown symbolic target: {module}::{symbol}"
                ))
            })
    }

    /// Returns an object or notification node by exact module/symbol
    /// (registry.py:253–255).
    pub(crate) fn resolve_node(&self, module: &str, symbol: &str) -> Option<&MibNode> {
        let record = self.modules.get(module)?;
        record
            .objects
            .get(symbol)
            .or_else(|| record.notifications.get(symbol))
    }

    /// Returns a type record from the local module or imported modules
    /// (registry.py:238–251). The first import that names `type_name` decides
    /// (a missing record there yields `None`, exactly like the reference).
    pub(crate) fn resolve_type(&self, module: &str, type_name: &str) -> Option<&MibTypeRecord> {
        let record = self.modules.get(module)?;
        if let Some(type_record) = record.types.get(type_name) {
            return Some(type_record);
        }
        for (imported_module, names) in &record.imports {
            if names.iter().any(|name| name == type_name) {
                return self
                    .modules
                    .get(imported_module)
                    .and_then(|imported| imported.types.get(type_name));
            }
        }
        None
    }

    /// Finds the closest known object for `oid` (registry.py:183–217):
    /// exact match first (sidecar accelerator, then the node index), then
    /// longest-prefix match, then `UnknownOidError`.
    pub(crate) fn lookup_oid(&self, oid: &Oid) -> Result<OidMatch, TranslationError> {
        if let Some(node) = self.lookup_exact(oid) {
            return Ok(Self::match_for_node(oid, node, Oid::empty()));
        }

        let arcs = oid.arcs();
        for prefix_len in (1..arcs.len()).rev() {
            let prefix = Oid::from_arcs_unchecked(arcs[..prefix_len].to_vec());
            if let Some(node) = self.lookup_exact(&prefix) {
                let suffix = Oid::from_arcs_unchecked(arcs[prefix_len..].to_vec());
                return Ok(Self::match_for_node(oid, node, suffix));
            }
        }
        Err(TranslationError::UnknownOid(format!(
            "Unknown numeric OID: {}",
            oid.display()
        )))
    }

    /// Renders a numeric OID using the user-facing symbolic display policy
    /// (registry.py:229–232).
    pub(crate) fn display_symbolic(&self, oid: &Oid) -> Result<String, TranslationError> {
        let match_ = self.lookup_oid(oid)?;
        Ok(self.display_symbolic_from_match(&match_))
    }

    /// Renders a resolved OID match (registry.py:234–236).
    pub(crate) fn display_symbolic_from_match(&self, match_: &OidMatch) -> String {
        self.display_match(match_).symbolic()
    }

    /// Resolves value-rendering metadata for the object owning `oid`
    /// (registry.py:257–272). `None` when no object matches.
    pub(crate) fn lookup_metadata(&self, oid: &Oid) -> Option<NodeValueMetadata> {
        let match_ = self.lookup_oid(oid).ok()?;
        let node = self.resolve_node(&match_.module, &match_.symbol)?;
        Some(NodeValueMetadata {
            enums: node.enums.clone(),
            units: node.units.clone(),
            syntax: node.syntax.clone(),
        })
    }

    /// Iterates object nodes, optionally filtered by module and object type
    /// (bundle.py:56–69).
    pub(crate) fn iter_objects<'a>(
        &'a self,
        module: Option<&str>,
        type_filter: Option<&str>,
    ) -> impl Iterator<Item = &'a MibNode> {
        self.modules
            .iter()
            .filter(move |(mod_name, _)| module.is_none_or(|m| mod_name.as_str() == m))
            .flat_map(move |(_, record)| record.objects.values())
            .filter(move |node| type_filter.is_none_or(|filter| node.object_type == filter))
    }

    /// Iterates notification nodes, optionally filtered by module
    /// (bundle.py:71–79).
    pub(crate) fn iter_notifications<'a>(
        &'a self,
        module: Option<&str>,
    ) -> impl Iterator<Item = &'a MibNode> {
        self.modules
            .iter()
            .filter(move |(mod_name, _)| module.is_none_or(|m| mod_name.as_str() == m))
            .flat_map(move |(_, record)| record.notifications.values())
    }

    /// Case-insensitive substring search over node names and descriptions
    /// (bundle.py:82–110).
    pub(crate) fn search(
        &self,
        query: &str,
        module: Option<&str>,
        type_filter: Option<&str>,
        limit: usize,
    ) -> Vec<&MibNode> {
        let needle = query.to_lowercase();
        let mut results = Vec::new();
        for (mod_name, record) in &self.modules {
            if module.is_some_and(|m| mod_name != m) {
                continue;
            }
            let mut candidates: Vec<&MibNode> = Vec::new();
            if type_filter != Some("NOTIFICATION-TYPE") {
                candidates.extend(record.objects.values());
            }
            if type_filter != Some("OBJECT-TYPE") {
                candidates.extend(record.notifications.values());
            }
            for node in candidates {
                if type_filter.is_some_and(|filter| node.object_type != filter) {
                    continue;
                }
                let name_match = node.name.to_lowercase().contains(&needle);
                let description_match = node
                    .description
                    .as_deref()
                    .is_some_and(|d| d.to_lowercase().contains(&needle));
                if name_match || description_match {
                    results.push(node);
                    if results.len() >= limit {
                        return results;
                    }
                }
            }
        }
        results
    }

    /// Exact lookup through the sidecar accelerator first, then the node index
    /// (registry.py:274–278).
    fn lookup_exact(&self, oid: &Oid) -> Option<&MibNode> {
        if let Some(entry) = self.oid_index.get(oid) {
            return self.resolve_node(&entry.module, &entry.symbol);
        }
        self.node_oids
            .get(oid)
            .and_then(|(module, symbol)| self.resolve_node(module, symbol))
    }

    /// Builds the `OidMatch` view for a resolved node (registry.py:190–215).
    fn match_for_node(oid: &Oid, node: &MibNode, suffix: Oid) -> OidMatch {
        OidMatch {
            oid: oid.clone(),
            module: node.module.clone(),
            symbol: node.name.clone(),
            matched_oid: node.oid.clone(),
            suffix,
            class_name: Some(node.class_name.clone()),
            object_type: Some(node.object_type.clone()),
            nodetype: node.nodetype.clone(),
        }
    }

    /// Applies the display policy: an exact `OBJECT IDENTIFIER` ending in `.0`
    /// whose parent is a `scalar` `OBJECT-TYPE` renders as the parent with a
    /// `.0` suffix (registry.py:280–302).
    fn display_match(&self, match_: &OidMatch) -> OidMatch {
        let arcs = match_.oid.arcs();
        if !match_.suffix.arcs().is_empty()
            || match_.object_type.as_deref() != Some("OBJECT IDENTIFIER")
            || arcs.is_empty()
            || arcs.last() != Some(&0)
        {
            return match_.clone();
        }

        let parent_oid = Oid::from_arcs_unchecked(arcs[..arcs.len() - 1].to_vec());
        let Some(parent) = self
            .node_oids
            .get(&parent_oid)
            .and_then(|(module, symbol)| self.resolve_node(module, symbol))
        else {
            return match_.clone();
        };
        if parent.object_type != "OBJECT-TYPE" || parent.nodetype.as_deref() != Some("scalar") {
            return match_.clone();
        }

        OidMatch {
            oid: match_.oid.clone(),
            module: parent.module.clone(),
            symbol: parent.name.clone(),
            matched_oid: parent.oid.clone(),
            suffix: Oid::from_arcs_unchecked(vec![0]),
            class_name: Some(parent.class_name.clone()),
            object_type: Some(parent.object_type.clone()),
            nodetype: parent.nodetype.clone(),
        }
    }
}
