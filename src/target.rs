//! Target enum + FromStr (← _runtime.py, dissolved)

use std::str::FromStr;

use crate::error::{Error, TranslationError};
use crate::types::oid::Oid;

/// An unresolved target reference: a numeric OID or a `MODULE::symbol[.suffix]`
/// reference (← _runtime.py:Target; §5.5).
///
/// Symbolic targets resolve against a loaded MIB bundle; without one they
/// fail with [`TranslationError::UnknownSymbol`].
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Target {
    /// A numeric dotted OID (`1.3.6.1.2.1.1.3.0`).
    Numeric(Oid),
    /// A symbolic reference (`IF-MIB::ifDescr.1`).
    Symbolic {
        /// MIB module name.
        module: String,
        /// Symbol within the module.
        symbol: String,
        /// Numeric suffix after the symbol.
        suffix: Vec<u32>,
    },
}

impl Target {
    /// The `MODULE::symbol[.suffix]` display form (← registry.py:109–125).
    #[must_use]
    pub fn symbolic_text(&self) -> String {
        match self {
            Target::Numeric(oid) => oid.display(),
            Target::Symbolic {
                module,
                symbol,
                suffix,
            } => {
                let mut text = format!("{module}::{symbol}");
                if !suffix.is_empty() {
                    text.push('.');
                    text.push_str(
                        &suffix
                            .iter()
                            .map(u32::to_string)
                            .collect::<Vec<_>>()
                            .join("."),
                    );
                }
                text
            }
        }
    }
}

/// True when every dotted segment is a non-negative digit run
/// (← registry.py:103–106).
fn is_numeric_oid_text(text: &str) -> bool {
    // Python parity: leading dots are stripped before the digit-run check
    // (registry.py:103–105); `Oid::parse` tolerates the leading dot too.
    let stripped = text.trim_start_matches('.');
    !stripped.is_empty()
        && stripped
            .split('.')
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
}

impl FromStr for Target {
    type Err = TranslationError;

    fn from_str(raw: &str) -> Result<Self, TranslationError> {
        let stripped = raw.trim();
        if let Some(index) = stripped.find("::") {
            let module = &stripped[..index];
            let rest = &stripped[index + 2..];
            if module.is_empty() || rest.is_empty() {
                return Err(TranslationError::UnknownSymbol(format!(
                    "Symbolic target must use MODULE::symbol form: {raw}"
                )));
            }
            let (symbol, suffix_text) = match rest.split_once('.') {
                Some((symbol, suffix)) => (symbol, Some(suffix)),
                None => (rest, None),
            };
            if symbol.is_empty() {
                return Err(TranslationError::UnknownSymbol(format!(
                    "Symbolic target must use MODULE::symbol form: {raw}"
                )));
            }
            let mut suffix = Vec::new();
            if let Some(suffix_text) = suffix_text {
                for part in suffix_text.split('.') {
                    if part.is_empty() || !part.chars().all(|c| c.is_ascii_digit()) {
                        return Err(TranslationError::UnknownSymbol(format!(
                            "Symbolic target suffix must be numeric: {raw}"
                        )));
                    }
                    match part.parse::<u32>() {
                        Ok(arc) => suffix.push(arc),
                        Err(_) => {
                            return Err(TranslationError::UnknownSymbol(format!(
                                "Symbolic target suffix arc out of range: {raw}"
                            )));
                        }
                    }
                }
            }
            return Ok(Target::Symbolic {
                module: module.to_string(),
                symbol: symbol.to_string(),
                suffix,
            });
        }
        if is_numeric_oid_text(stripped) {
            return Oid::parse(stripped)
                .map(Target::Numeric)
                .map_err(TranslationError::InvalidOid);
        }
        Err(TranslationError::UnknownSymbol(format!(
            "Unrecognized target format: {raw}"
        )))
    }
}

/// Lenient conversion for the ergonomic `impl Into<Target>` manager/notifier
/// arguments. Anything `FromStr` cannot parse is preserved as a `Symbolic`
/// with an empty module; `normalize_targets` rejects it with the
/// "Unrecognized target format" message (the reference validates at
/// normalize time, _runtime.py:24–38).
impl From<&str> for Target {
    fn from(raw: &str) -> Self {
        match Target::from_str(raw) {
            Ok(target) => target,
            Err(_) => Target::Symbolic {
                module: String::new(),
                symbol: raw.to_string(),
                suffix: Vec::new(),
            },
        }
    }
}

impl From<Oid> for Target {
    fn from(oid: Oid) -> Self {
        Target::Numeric(oid)
    }
}

/// Arc-sequence targets (`1.3.6.1` as `&[u32]`). Invalid arc sequences fall
/// back to the unrecognized sentinel so `normalize_targets` reports the
/// reference's "Unrecognized target format" error.
impl From<&[u32]> for Target {
    fn from(arcs: &[u32]) -> Self {
        match Oid::from_arcs(arcs) {
            Ok(oid) => Target::Numeric(oid),
            Err(_) => Target::Symbolic {
                module: String::new(),
                symbol: arcs
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join("."),
                suffix: Vec::new(),
            },
        }
    }
}

impl From<Vec<u32>> for Target {
    fn from(arcs: Vec<u32>) -> Self {
        Target::from(arcs.as_slice())
    }
}

/// Resolves a list of targets to numeric OIDs (← _runtime.py:normalize_targets).
///
/// Empty input is rejected. Symbolic targets require a loaded bundle; without
/// one they fail with `UnknownSymbol` (`_runtime.py:24–38`).
pub fn normalize_targets(
    targets: &[Target],
    bundle: Option<&crate::mib::MibBundle>,
) -> Result<Vec<Oid>, Error> {
    if targets.is_empty() {
        return Err(Error::InvalidInput(
            "At least one target is required".to_string(),
        ));
    }
    let mut oids = Vec::with_capacity(targets.len());
    for target in targets {
        match target {
            Target::Numeric(oid) => oids.push(oid.clone()),
            Target::Symbolic {
                module,
                symbol,
                suffix: _,
            } => {
                if module.is_empty() {
                    // From<&str> fallback for unrecognized input.
                    return Err(Error::Translation(TranslationError::UnknownSymbol(
                        format!("Unrecognized target format: {symbol}"),
                    )));
                }
                let Some(bundle) = bundle else {
                    return Err(Error::Translation(TranslationError::UnknownSymbol(
                        format!("Symbolic target requires a loaded bundle: {module}::{symbol}"),
                    )));
                };
                oids.push(bundle.resolve(target)?);
            }
        }
    }
    Ok(oids)
}

/// Resolves a single target to a numeric OID.
pub fn normalize_target(
    target: &Target,
    bundle: Option<&crate::mib::MibBundle>,
) -> Result<Oid, Error> {
    normalize_targets(std::slice::from_ref(target), bundle).map(|mut oids| oids.remove(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn parses_numeric_targets() {
        let target = Target::from_str("1.3.6.1.2.1.1.3.0").unwrap();
        assert_eq!(
            target,
            Target::Numeric(Oid::from_arcs(&[1, 3, 6, 1, 2, 1, 1, 3, 0]).unwrap())
        );
        assert_eq!(target.symbolic_text(), "1.3.6.1.2.1.1.3.0");
    }

    #[test]
    fn parses_symbolic_targets_with_suffix() {
        let target = Target::from_str("IF-MIB::ifDescr.1").unwrap();
        assert_eq!(
            target,
            Target::Symbolic {
                module: "IF-MIB".to_string(),
                symbol: "ifDescr".to_string(),
                suffix: vec![1],
            }
        );
        assert_eq!(target.symbolic_text(), "IF-MIB::ifDescr.1");
    }

    #[test]
    fn rejects_unrecognized_text() {
        let err = Target::from_str("not-an-oid").unwrap_err();
        assert!(err.to_string().contains("Unrecognized target format"));
    }

    #[test]
    fn rejects_malformed_symbolic_forms() {
        assert!(Target::from_str("::ifDescr").is_err());
        assert!(Target::from_str("IF-MIB::").is_err());
        assert!(Target::from_str("IF-MIB::ifDescr.x").is_err());
        assert!(Target::from_str("IF-MIB::ifDescr.1.2.x").is_err());
    }

    #[test]
    fn rejects_negative_arcs_and_overflow() {
        assert!(Target::from_str("1.3.-1").is_err());
        assert!(Target::from_str("1.3.99999999999").is_err());
    }

    #[test]
    fn parses_leading_dot_numeric_targets() {
        // Python parity: ".1.3.6" is numeric text and parses (registry.py:103).
        let target = Target::from_str(".1.3.6.1.2.1.1.3.0").unwrap();
        assert_eq!(
            target,
            Target::Numeric(Oid::from_arcs(&[1, 3, 6, 1, 2, 1, 1, 3, 0]).unwrap())
        );
    }

    #[test]
    fn trims_whitespace() {
        assert_eq!(
            Target::from_str(" 1.3.6.1.2.1.1.3.0 ").unwrap(),
            Target::from_str("1.3.6.1.2.1.1.3.0").unwrap()
        );
    }

    #[test]
    fn normalize_requires_at_least_one_target() {
        let err = normalize_targets(&[], None).unwrap_err();
        assert_eq!(
            err,
            Error::InvalidInput("At least one target is required".to_string())
        );
    }

    #[test]
    fn normalize_rejects_symbolic_without_bundle() {
        let target = Target::from_str("IF-MIB::ifDescr.1").unwrap();
        let err = normalize_targets(&[target], None).unwrap_err();
        assert!(
            err.to_string()
                .contains("Symbolic target requires a loaded bundle")
        );
    }

    #[test]
    fn normalize_rejects_unrecognized_text() {
        let target = Target::from("not-an-oid");
        let err = normalize_targets(&[target], None).unwrap_err();
        assert!(
            err.to_string()
                .contains("Unrecognized target format: not-an-oid")
        );
    }

    #[test]
    fn normalize_returns_oid_list() {
        let targets = vec![
            Target::from("1.3.6.1.2.1.1.3.0"),
            Target::from("1.3.6.1.2.1.1.5.0"),
        ];
        let oids = normalize_targets(&targets, None).unwrap();
        assert_eq!(oids.len(), 2);
        assert_eq!(
            oids[0],
            Oid::from_arcs(&[1, 3, 6, 1, 2, 1, 1, 3, 0]).unwrap()
        );
    }
}
