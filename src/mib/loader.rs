//! Bundle loading entry points (← mib/loader.py)
//!
//! `load_bundle` accepts a module JSON file or a bundle directory. A directory
//! may carry an optional `manifest.json` inventory (with the `schema_version`
//! gate) and an optional `oid_index.json` accelerator sidecar; without a
//! manifest every `*.json` module file except the two sidecars is loaded in
//! sorted name order. Duplicate module names are rejected deterministically,
//! naming both conflicting files (loader.py:47–72).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::error::{BundleError, Error};
use crate::mib::MibBundle;
use crate::mib::model::{MibModuleRecord, normalize_module_payload, validate_schema_version};
use crate::mib::registry::{OidIndexEntry, RegistryInner};
use crate::types::oid::Oid;

/// The two sidecar filenames excluded from manifest-less directory discovery
/// (loader.py:22).
const SIDECAR_FILENAMES: [&str; 2] = ["manifest.json", "oid_index.json"];

/// Loads a bundle from a module JSON file or a directory of module JSON files
/// (loader.py:31–44).
pub fn load_bundle(path: impl AsRef<Path>) -> Result<MibBundle, Error> {
    let source = expanduser(path.as_ref());
    if source.is_file() {
        let module_record = load_module_json(&source)?;
        let mut modules = BTreeMap::new();
        modules.insert(module_record.module.clone(), module_record);
        let registry = RegistryInner::new(modules, BTreeMap::new());
        return Ok(MibBundle::new(registry, source));
    }

    if source.is_dir() {
        let loaded = discover_directory(&source)?;
        let registry = build_registry(&loaded.module_paths, loaded.oid_index)?;
        return Ok(MibBundle::new(registry, source));
    }

    Err(BundleError::Validation {
        path: source.display().to_string(),
        message: "Bundle path does not exist".to_string(),
    }
    .into())
}

/// A discovered bundle directory: the module files to load plus the optional
/// accelerator index (loader.py:25–29).
struct LoadedDirectory {
    module_paths: Vec<PathBuf>,
    oid_index: BTreeMap<Oid, OidIndexEntry>,
}

/// Loads module files into a registry, rejecting duplicate module names
/// (loader.py:47–72).
fn build_registry(
    module_paths: &[PathBuf],
    oid_index: BTreeMap<Oid, OidIndexEntry>,
) -> Result<RegistryInner, BundleError> {
    let mut modules: BTreeMap<String, MibModuleRecord> = BTreeMap::new();
    let mut module_sources: BTreeMap<String, PathBuf> = BTreeMap::new();
    for module_path in module_paths {
        let module = load_module_json(module_path)?;
        if let Some(earlier_path) = module_sources.get(&module.module) {
            return Err(BundleError::Validation {
                path: module_path.display().to_string(),
                message: format!(
                    "Duplicate module {:?} declared by {} and {}",
                    module.module,
                    earlier_path.display(),
                    module_path.display()
                ),
            });
        }
        module_sources.insert(module.module.clone(), module_path.clone());
        modules.insert(module.module.clone(), module);
    }
    Ok(RegistryInner::new(modules, oid_index))
}

/// Loads and normalizes one module JSON file.
fn load_module_json(path: &Path) -> Result<MibModuleRecord, BundleError> {
    let payload = read_json(path)?;
    normalize_module_payload(&payload, path)
}

/// Discovers a bundle directory's module files and optional accelerator
/// (loader.py:80–102).
fn discover_directory(path: &Path) -> Result<LoadedDirectory, BundleError> {
    let manifest_path = path.join("manifest.json");
    let module_paths = if manifest_path.exists() {
        module_paths_from_manifest(path, &manifest_path)?
    } else {
        directory_module_paths(path)?
    };

    if module_paths.is_empty() {
        return Err(BundleError::Validation {
            path: path.display().to_string(),
            message: "No module JSON files were found in bundle directory".to_string(),
        });
    }

    let oid_index_path = path.join("oid_index.json");
    let oid_index = if oid_index_path.exists() {
        load_oid_index(&oid_index_path)?
    } else {
        BTreeMap::new()
    };
    Ok(LoadedDirectory {
        module_paths,
        oid_index,
    })
}

/// Sorted `*.json` module files excluding the sidecars (loader.py:86–92).
fn directory_module_paths(path: &Path) -> Result<Vec<PathBuf>, BundleError> {
    let entries = fs::read_dir(path).map_err(|e| BundleError::Load(e.to_string()))?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| BundleError::Load(e.to_string()))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.ends_with(".json") && !SIDECAR_FILENAMES.contains(&name.as_ref()) {
            paths.push(entry.path());
        }
    }
    paths.sort();
    Ok(paths)
}

/// Reads the manifest and resolves its module inventory (loader.py:105–143).
///
/// Containment follows symlinks: `fs::canonicalize` resolves the module path
/// the way Python's `Path.resolve()` does (loader.py:128–133), so a manifest
/// entry pointing through a symlink at a file outside the bundle directory is
/// rejected. For paths that do not exist yet (checked after containment),
/// canonicalization fails and a lexical normalization is used instead —
/// matching `Path.resolve(strict=False)`.
fn module_paths_from_manifest(
    bundle_dir: &Path,
    manifest_path: &Path,
) -> Result<Vec<PathBuf>, BundleError> {
    let manifest = read_json(manifest_path)?;
    if !manifest.is_object() {
        return Err(BundleError::Validation {
            path: manifest_path.display().to_string(),
            message: "Manifest must be a JSON object".to_string(),
        });
    }
    let manifest_obj = manifest.as_object().expect("checked above");
    let producer = manifest_obj
        .get("producer_version")
        .and_then(serde_json::Value::as_str);
    validate_schema_version(manifest_obj.get("schema_version"), manifest_path, producer)?;

    let raw_modules = manifest_obj.get("modules");
    let modules = raw_modules.and_then(serde_json::Value::as_array);
    let Some(modules) = modules else {
        return Err(BundleError::Validation {
            path: manifest_path.display().to_string(),
            message: "Manifest is missing a valid 'modules' list".to_string(),
        });
    };
    if modules.is_empty() {
        return Err(BundleError::Validation {
            path: manifest_path.display().to_string(),
            message: "Manifest is missing a valid 'modules' list".to_string(),
        });
    }

    let bundle_dir_resolved = fs::canonicalize(bundle_dir).unwrap_or_else(|_| {
        // The bundle directory exists (we just read the manifest from it), but
        // canonicalize can still fail on unusual mounts; fall back to a
        // lexical normalization so the containment check stays total.
        lexical_resolve(bundle_dir)
    });
    let mut module_paths = Vec::new();
    let mut seen_files: BTreeSet<PathBuf> = BTreeSet::new();
    for entry in modules {
        let file_name = manifest_module_filename(entry, manifest_path)?;
        let module_path = bundle_dir.join(&file_name);
        let resolved =
            fs::canonicalize(&module_path).unwrap_or_else(|_| lexical_resolve(&module_path));
        if !resolved.starts_with(&bundle_dir_resolved) {
            return Err(BundleError::Validation {
                path: manifest_path.display().to_string(),
                message: "Manifest module file must stay within the bundle directory".to_string(),
            });
        }
        if seen_files.contains(&resolved) {
            continue;
        }
        if !module_path.exists() {
            return Err(BundleError::Validation {
                path: manifest_path.display().to_string(),
                message: format!("Manifest references a missing module file {file_name:?}"),
            });
        }
        seen_files.insert(resolved);
        module_paths.push(module_path);
    }
    Ok(module_paths)
}

/// Extracts a module filename from a manifest entry (loader.py:146–156).
fn manifest_module_filename(
    entry: &serde_json::Value,
    manifest_path: &Path,
) -> Result<String, BundleError> {
    if let Some(file_name) = entry.as_str() {
        return Ok(file_name.to_string());
    }
    if let Some(entry_obj) = entry.as_object()
        && let Some(file_name) = entry_obj.get("file").and_then(serde_json::Value::as_str)
        && !file_name.is_empty()
    {
        return Ok(file_name.to_string());
    }
    Err(BundleError::Validation {
        path: manifest_path.display().to_string(),
        message: "Manifest modules must be strings or objects containing a 'file' field"
            .to_string(),
    })
}

/// Loads the `oid_index.json` accelerator sidecar (loader.py:159–186).
fn load_oid_index(path: &Path) -> Result<BTreeMap<Oid, OidIndexEntry>, BundleError> {
    let payload = read_json(path)?;
    if !payload.is_object() {
        return Err(BundleError::Validation {
            path: path.display().to_string(),
            message: "OID index must be a JSON object".to_string(),
        });
    }
    let raw_index = payload
        .as_object()
        .and_then(|obj| obj.get("oids"))
        .unwrap_or(&payload);
    if !raw_index.is_object() {
        return Err(BundleError::Validation {
            path: path.display().to_string(),
            message: "OID index entries must be a JSON object".to_string(),
        });
    }

    let mut normalized = BTreeMap::new();
    for (raw_oid, entry) in raw_index.as_object().expect("checked above") {
        let oid = Oid::parse(raw_oid).map_err(|e| BundleError::Validation {
            path: path.display().to_string(),
            message: format!(
                "OID index key {raw_oid:?} is not a valid dotted-string OID: {}",
                e.0
            ),
        })?;
        let Some(entry_obj) = entry.as_object() else {
            return Err(BundleError::Validation {
                path: path.display().to_string(),
                message: "OID index entries must be JSON objects".to_string(),
            });
        };
        let module = entry_obj.get("module").and_then(serde_json::Value::as_str);
        let symbol = entry_obj
            .get("object")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .or_else(|| {
                entry_obj
                    .get("symbol")
                    .and_then(serde_json::Value::as_str)
                    .filter(|value| !value.is_empty())
            });
        let (Some(module), Some(symbol)) = (module, symbol) else {
            return Err(BundleError::Validation {
                path: path.display().to_string(),
                message: "OID index entries must contain string 'module' and 'object' fields"
                    .to_string(),
            });
        };
        normalized.insert(
            oid,
            OidIndexEntry {
                module: module.to_string(),
                symbol: symbol.to_string(),
            },
        );
    }
    Ok(normalized)
}

/// Reads and JSON-parses a bundle artifact (loader.py:189–196). Missing files
/// and malformed JSON map to the reference's messages.
fn read_json(path: &Path) -> Result<serde_json::Value, BundleError> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(BundleError::Validation {
                path: path.display().to_string(),
                message: "Missing bundle artifact".to_string(),
            });
        }
        Err(error) => {
            return Err(BundleError::Load(format!(
                "Failed to read {}: {error}",
                path.display()
            )));
        }
    };
    serde_json::from_str(&text).map_err(|error| BundleError::Validation {
        path: path.display().to_string(),
        message: format!("Invalid JSON: {error}"),
    })
}

/// Lexically normalizes a path (`Path::resolve`-like, without touching the
/// filesystem) for the manifest in-bundle containment check (loader.py:129).
fn lexical_resolve(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// `~`/`~/…` expansion for the bundle path (loader.py:32). On unix the
/// reference's `Path.expanduser()` `~user` form is also handled (§8); on
/// non-unix the documented `~`/`~/`-only limitation stays.
#[cfg(unix)]
fn expanduser(path: &Path) -> PathBuf {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    expanduser_with(path, home.as_deref(), &passwd)
}

/// Pure `~`/`~/`/`~user` expansion against explicit HOME and passwd content —
/// unit-testable with fixture content (no filesystem access).
#[cfg(unix)]
fn expanduser_with(path: &Path, home: Option<&Path>, passwd_content: &str) -> PathBuf {
    let text = path.to_string_lossy();
    if text == "~" {
        return match home {
            Some(home) => home.to_path_buf(),
            None => path.to_path_buf(),
        };
    }
    if let Some(rest) = text.strip_prefix("~/") {
        return match home {
            Some(home) => home.join(rest),
            None => path.to_path_buf(),
        };
    }
    if let Some(rest) = text.strip_prefix('~') {
        let (user, remainder) = split_tilde_user(rest);
        if let Some(home) = passwd_home_for(passwd_content, &user) {
            return PathBuf::from(home).join(remainder);
        }
    }
    path.to_path_buf()
}

/// `~`/`~/…` expansion for the bundle path (loader.py:32); the reference's
/// `~user` form needs the pwd module, so the documented limitation stays on
/// non-unix (§8).
#[cfg(not(unix))]
fn expanduser(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return path.to_path_buf();
    };
    if text == "~" {
        return home;
    }
    if let Some(rest) = text.strip_prefix("~/") {
        return home.join(rest);
    }
    path.to_path_buf()
}

/// Splits the text after the leading `~` of a `~user/…` path into the user
/// name and the path remainder (empty when the path is exactly `~user`).
#[cfg(unix)]
fn split_tilde_user(rest: &str) -> (String, &str) {
    match rest.split_once('/') {
        Some((user, remainder)) => (user.to_string(), remainder),
        None => (rest.to_string(), ""),
    }
}

/// Looks up `user`'s home directory (passwd field 6) in `/etc/passwd`
/// `content`. Malformed lines (wrong field count) and empty home fields are
/// skipped; the first well-formed match wins. `None` when the user is absent —
/// the caller falls through to the literal path, which `load_bundle` rejects
/// with "Bundle path does not exist".
#[cfg(unix)]
fn passwd_home_for<'a>(content: &'a str, user: &str) -> Option<&'a str> {
    content.lines().find_map(|line| {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() != 7 || fields[5].is_empty() {
            return None;
        }
        (fields[0] == user).then_some(fields[5])
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_json_reports_missing_artifact() {
        // loader.py:189–193 — the "Missing bundle artifact" contract is only
        // reachable through the internal reader (public paths pre-check
        // existence), so it is pinned here.
        let path = PathBuf::from("/definitely/not/here.json");
        let err = read_json(&path).unwrap_err();
        assert!(matches!(
            err,
            BundleError::Validation { message, .. }
                if message == "Missing bundle artifact"
        ));
    }

    #[cfg(unix)]
    mod expanduser_unix {
        use super::*;

        /// A fixture `/etc/passwd`-shaped content block.
        const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\n\
                              alice:x:1000:1000:Alice:/home/alice:/bin/sh\n\
                              this line is malformed\n\
                              bob:x:1001:1001::/home/bob:/usr/sbin/nologin\n\
                              :x:1002:1002:::/bin/false\n";

        fn home(home: &str) -> Option<&Path> {
            Some(Path::new(home))
        }

        #[test]
        fn passwd_home_for_finds_valid_user() {
            assert_eq!(passwd_home_for(PASSWD, "alice"), Some("/home/alice"));
            assert_eq!(passwd_home_for(PASSWD, "bob"), Some("/home/bob"));
        }

        #[test]
        fn passwd_home_for_skips_malformed_lines() {
            // The malformed and empty-name lines must not confuse the parse.
            assert_eq!(passwd_home_for(PASSWD, "bob"), Some("/home/bob"));
            assert_eq!(passwd_home_for(PASSWD, "root"), Some("/root"));
        }

        #[test]
        fn passwd_home_for_unknown_user_is_none() {
            assert_eq!(passwd_home_for(PASSWD, "ghost"), None);
        }

        #[test]
        fn expanduser_known_user_substitutes_home() {
            assert_eq!(
                expanduser_with(Path::new("~alice"), home("/home/me"), PASSWD),
                PathBuf::from("/home/alice")
            );
            assert_eq!(
                expanduser_with(
                    Path::new("~bob/bundles/IF-MIB.json"),
                    home("/home/me"),
                    PASSWD
                ),
                PathBuf::from("/home/bob/bundles/IF-MIB.json")
            );
        }

        #[test]
        fn expanduser_unknown_user_falls_through() {
            // The literal path survives expansion and load_bundle then rejects
            // it with "Bundle path does not exist" (loader.rs:42–46) — the
            // reference's behavior for an unknown `~user`.
            let path = Path::new("~ghost/bundles/IF-MIB.json");
            assert_eq!(
                expanduser_with(path, home("/home/me"), PASSWD),
                path.to_path_buf()
            );
            let bare = Path::new("~ghost");
            assert_eq!(
                expanduser_with(bare, home("/home/me"), PASSWD),
                bare.to_path_buf()
            );
        }

        #[test]
        fn expanduser_unreadable_passwd_falls_through() {
            // An empty /etc/passwd parse (unreadable or absent file) keeps
            // `~user` literal while `~`/`~/` keep working.
            assert_eq!(
                expanduser_with(Path::new("~ghost/mib"), home("/home/me"), ""),
                PathBuf::from("~ghost/mib")
            );
        }

        #[test]
        fn expanduser_tilde_forms_are_unchanged() {
            // `~` and `~/…` behave exactly as before: HOME-driven, and literal
            // when HOME is unset.
            assert_eq!(
                expanduser_with(Path::new("~"), home("/home/me"), PASSWD),
                PathBuf::from("/home/me")
            );
            assert_eq!(
                expanduser_with(Path::new("~/bundles"), home("/home/me"), PASSWD),
                PathBuf::from("/home/me/bundles")
            );
            assert_eq!(
                expanduser_with(Path::new("~"), None, PASSWD),
                PathBuf::from("~")
            );
            assert_eq!(
                expanduser_with(Path::new("~/bundles"), None, PASSWD),
                PathBuf::from("~/bundles")
            );
        }
    }
}
