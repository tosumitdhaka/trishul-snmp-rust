//! MibBundle facade (Clone/Arc) (← mib/bundle.py)
//!
//! The public bundle abstraction: loaded compiled-JSON MIB modules plus the
//! in-memory indexes for translation and enrichment. `MibBundle` is `Clone`
//! via `Arc` internals (§3), so it threads cheaply through sessions, manager
//! operations, and listeners.

pub mod loader;
pub mod model;
pub mod registry;
pub mod render;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use crate::error::{Error, TranslationError};
use crate::mib::registry::{NodeValueMetadata, RegistryInner};
use crate::mib::render::enrich_varbinds;
use crate::target::Target;
use crate::types::oid::Oid;
use crate::types::varbind::{OidMatch, VarBind};

pub use loader::load_bundle;
pub use model::{MibMemberRef, MibModuleRecord, MibNode, MibTypeRecord};

/// A loaded MIB artifact set used for translation and enrichment
/// (← bundle.py:MibBundle; §5.8).
#[derive(Clone, Debug)]
pub struct MibBundle {
    inner: Arc<RegistryInner>,
    source: PathBuf,
}

impl MibBundle {
    /// Builds a bundle over a registry (loader.rs; `source` is the loaded
    /// file or directory).
    pub(crate) fn new(registry: RegistryInner, source: PathBuf) -> Self {
        Self {
            inner: Arc::new(registry),
            source,
        }
    }

    /// The loaded module file or bundle directory (bundle.py:18).
    #[must_use]
    pub fn source(&self) -> &Path {
        &self.source
    }

    /// The loaded module records keyed by module name (bundle.py:20–22).
    #[must_use]
    pub fn modules(&self) -> &BTreeMap<String, MibModuleRecord> {
        self.inner.modules()
    }

    /// Translates symbolic targets to numeric OIDs and vice versa
    /// (bundle.py:24–26; registry.py:219–227).
    pub fn translate(&self, target: &str) -> Result<String, Error> {
        let stripped = target.trim();
        if stripped.is_empty() {
            return Err(Error::Translation(TranslationError::Message(
                "Translation target cannot be empty".to_string(),
            )));
        }
        if !is_numeric_oid_text(stripped) && stripped.contains("::") {
            let target = Target::from_str(stripped)?;
            let oid = self.resolve(&target)?;
            return Ok(oid.display());
        }
        let oid = Oid::parse(stripped).map_err(TranslationError::InvalidOid)?;
        self.display_symbolic(&oid)
    }

    /// Renders a numeric OID using the user-facing symbolic display policy
    /// (bundle.py:28–30; registry.py:229–232). Errors with
    /// [`TranslationError::UnknownOid`] when nothing matches.
    pub fn display_symbolic(&self, oid: &Oid) -> Result<String, Error> {
        Ok(self.inner.display_symbolic(oid)?)
    }

    /// Renders a resolved OID match using the user-facing display policy
    /// (bundle.py:32–34).
    #[must_use]
    pub fn display_symbolic_from_match(&self, match_: &OidMatch) -> String {
        self.inner.display_symbolic_from_match(match_)
    }

    /// Resolves `MODULE::symbol[.suffix]` to a numeric OID (bundle.py:36–38;
    /// registry.py:175–181). Numeric targets pass through unchanged.
    pub fn resolve(&self, target: &Target) -> Result<Oid, Error> {
        match target {
            Target::Numeric(oid) => Ok(oid.clone()),
            Target::Symbolic {
                module,
                symbol,
                suffix,
            } => {
                if module.is_empty() {
                    return Err(Error::Translation(TranslationError::UnknownSymbol(
                        format!("Unrecognized target format: {symbol}"),
                    )));
                }
                let mut arcs = self.inner.resolve_node_oid(module, symbol)?.arcs().to_vec();
                arcs.extend(suffix.iter().copied());
                Oid::from_arcs(&arcs)
                    .map_err(|e| Error::Translation(TranslationError::InvalidOid(e)))
            }
        }
    }

    /// Finds the closest known object for `oid` (bundle.py:40–42;
    /// registry.py:183–217).
    pub fn lookup(&self, oid: &Oid) -> Result<OidMatch, TranslationError> {
        self.inner.lookup_oid(oid)
    }

    /// Resolves value-rendering metadata (enums/units/syntax) for the object
    /// owning `oid` (bundle.py:44–46).
    #[must_use]
    pub fn lookup_metadata(&self, oid: &Oid) -> Option<NodeValueMetadata> {
        self.inner.lookup_metadata(oid)
    }

    /// Resolves a local or imported textual convention (bundle.py:48–50).
    #[must_use]
    pub fn resolve_type(&self, module: &str, type_name: &str) -> Option<&MibTypeRecord> {
        self.inner.resolve_type(module, type_name)
    }

    /// Resolves an exact object or notification record (bundle.py:52–54).
    #[must_use]
    pub fn resolve_node(&self, module: &str, symbol: &str) -> Option<&MibNode> {
        self.inner.resolve_node(module, symbol)
    }

    /// Iterates object nodes, optionally filtered by module and object type
    /// (bundle.py:56–69).
    pub fn iter_objects<'a>(
        &'a self,
        module: Option<&str>,
        type_filter: Option<&str>,
    ) -> impl Iterator<Item = &'a MibNode> {
        self.inner.iter_objects(module, type_filter)
    }

    /// Iterates notification nodes, optionally filtered by module
    /// (bundle.py:71–79).
    pub fn iter_notifications<'a>(
        &'a self,
        module: Option<&str>,
    ) -> impl Iterator<Item = &'a MibNode> {
        self.inner.iter_notifications(module)
    }

    /// Case-insensitive substring search over node names and descriptions
    /// (bundle.py:82–110).
    #[must_use]
    pub fn search(
        &self,
        query: &str,
        module: Option<&str>,
        type_filter: Option<&str>,
        limit: usize,
    ) -> Vec<&MibNode> {
        self.inner.search(query, module, type_filter, limit)
    }

    /// Attaches symbolic names and value metadata to the varbinds
    /// (render.py:19–60).
    #[must_use]
    pub fn enrich(&self, varbinds: Vec<VarBind>) -> Vec<VarBind> {
        enrich_varbinds(Some(self), varbinds)
    }
}

/// True when every dotted segment is a non-negative digit run
/// (registry.py:103–106).
fn is_numeric_oid_text(text: &str) -> bool {
    let stripped = text.trim_start_matches('.');
    !stripped.is_empty()
        && stripped
            .split('.')
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
}
