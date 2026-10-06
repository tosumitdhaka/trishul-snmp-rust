//! Shared CLI argument plumbing: security parsing, secret-via-env resolution,
//! notification varbind / value parsing, and version-specific flag validation
//! (← cli/common.py). Every error message is the reference's exact string —
//! the CLI tests pin them.
//!
//! `--auth-key-env`/`--priv-key-env` name an environment variable at runtime;
//! the passphrase is read from it here (`_resolve_secret`, common.py:557–579).
//! The clap `env` feature is not used because the variable name is a user
//! value, not a static attribute.

use std::net::Ipv4Addr;
use std::str::FromStr;

use crate::cli::args::{HiddenLocalEngineArgs, LocalEngineArgs, SecurityArgs, UsmArgs, V1TrapArgs};
use crate::mib::MibBundle;
use crate::security::usm::kdf::{AuthProtocol, PrivProtocol};
use crate::security::usm::{AuthKey, PrivKey, UsmLocalEngine, UsmUser};
use crate::target::Target;
use crate::types::oid::Oid;
use crate::types::value::SnmpValue;

/// The local-engine flag group, shared by the visible (trap) and hidden
/// (inform) variants so both can feed the same validation.
pub trait HasLocalEngine {
    /// The `--local-engine-id` value.
    fn local_engine_id(&self) -> Option<&str>;
    /// The `--local-engine-boots` value.
    fn local_engine_boots(&self) -> Option<i64>;
    /// The `--local-engine-time` value.
    fn local_engine_time(&self) -> Option<i64>;
}

impl HasLocalEngine for LocalEngineArgs {
    fn local_engine_id(&self) -> Option<&str> {
        self.local_engine_id.as_deref()
    }
    fn local_engine_boots(&self) -> Option<i64> {
        self.local_engine_boots
    }
    fn local_engine_time(&self) -> Option<i64> {
        self.local_engine_time
    }
}

impl HasLocalEngine for HiddenLocalEngineArgs {
    fn local_engine_id(&self) -> Option<&str> {
        self.local_engine_id.as_deref()
    }
    fn local_engine_boots(&self) -> Option<i64> {
        self.local_engine_boots
    }
    fn local_engine_time(&self) -> Option<i64> {
        self.local_engine_time
    }
}

/// A validated v1/v2c or v3 security configuration (common.py:CliSecurity).
#[derive(Clone, Debug)]
pub enum CliSecurity {
    /// v1/v2c community security.
    Community {
        /// The effective community (default "public").
        community: String,
        /// The wire version ("1" or "2c").
        version: String,
    },
    /// v3 USM security.
    V3 {
        /// The validated user.
        user: UsmUser,
        /// Context name bytes.
        context_name: Vec<u8>,
        /// Sender-authoritative engine for traps, when supplied.
        local_engine: Option<UsmLocalEngine>,
    },
}

/// A validated listener security configuration
/// (common.py:ListenerCliSecurity).
#[derive(Clone, Debug)]
pub enum ListenerCliSecurity {
    /// v1/v2c community listener; `None` allows every community.
    Community {
        /// Normalized community allow-list (empty entries dropped).
        communities: Option<Vec<String>>,
    },
    /// v3 USM listener.
    V3 {
        /// The validated user.
        user: UsmUser,
        /// The required sender-authoritative local engine.
        local_engine: UsmLocalEngine,
    },
}

/// Builds the validated v1/v2c/v3 security configuration from CLI arguments
/// (common.py:parse_cli_security).
pub fn parse_cli_security(
    security: &SecurityArgs,
    context_name: &str,
    require_local_engine: bool,
    allow_local_engine: bool,
    local_engine: &impl HasLocalEngine,
) -> Result<CliSecurity, String> {
    if security.snmp_version == "3" {
        if security.community.is_some() {
            return Err("--community is invalid with --snmp-version 3".to_string());
        }
        let local_engine = parse_local_engine(
            local_engine,
            require_local_engine,
            allow_local_engine,
            "trap",
        )?;
        let user = parse_v3_user(&security.usm)?;
        Ok(CliSecurity::V3 {
            user,
            context_name: context_name.as_bytes().to_vec(),
            local_engine,
        })
    } else {
        let community = parse_community_cli_security(security, context_name, local_engine)?;
        Ok(CliSecurity::Community {
            community,
            version: security.snmp_version.clone(),
        })
    }
}

/// Builds the validated listener security configuration
/// (common.py:parse_listener_cli_security).
pub fn parse_listener_cli_security(
    snmp_version: &str,
    communities: &[String],
    usm: &UsmArgs,
    local_engine: &impl HasLocalEngine,
) -> Result<ListenerCliSecurity, String> {
    if snmp_version == "3" {
        if !communities.is_empty() {
            return Err("--community is invalid with --snmp-version 3".to_string());
        }
        let user = parse_v3_user(usm)?;
        let local_engine = parse_local_engine(local_engine, true, true, "listener")?;
        Ok(ListenerCliSecurity::V3 {
            user,
            local_engine: local_engine.expect("required by the call above"),
        })
    } else {
        reject_community_usm_flags(usm, snmp_version)?;
        if local_engine_supplied(local_engine) {
            return Err(format!(
                "--local-engine-* options are invalid with --snmp-version {snmp_version}"
            ));
        }
        let normalized: Vec<String> = communities
            .iter()
            .filter(|c| !c.is_empty())
            .cloned()
            .collect();
        let communities = if normalized.is_empty() {
            None
        } else {
            Some(normalized)
        };
        Ok(ListenerCliSecurity::Community { communities })
    }
}

/// Builds the optional v3 user for offline decode commands
/// (common.py:parse_decode_notification_user).
pub fn parse_decode_notification_user(
    snmp_version: &str,
    usm: &UsmArgs,
) -> Result<Option<UsmUser>, String> {
    if snmp_version == "3" {
        return Ok(Some(parse_v3_user(usm)?));
    }
    reject_community_usm_flags(usm, snmp_version)?;
    Ok(None)
}

/// Validates SNMP-version-specific flag mixing for the trap command
/// (common.py:validate_trap_version_flags).
pub fn validate_trap_version_flags(
    snmp_version: &str,
    notification: &Option<String>,
    uptime: u32,
    v1_trap: &V1TrapArgs,
) -> Result<(), String> {
    if snmp_version == "1" {
        if notification.is_some() {
            return Err(
                "a positional notification OID is invalid with --snmp-version 1; use --enterprise"
                    .to_string(),
            );
        }
        if uptime != 0 {
            return Err("--uptime is invalid with --snmp-version 1; use --timestamp".to_string());
        }
        if v1_trap.enterprise.is_none() {
            return Err("--enterprise is required with --snmp-version 1".to_string());
        }
        return Ok(());
    }
    if v1_trap.enterprise.is_some() {
        return Err("--enterprise requires --snmp-version 1".to_string());
    }
    if v1_trap.agent_addr.is_some() {
        return Err("--agent-addr requires --snmp-version 1".to_string());
    }
    if v1_trap.generic_trap.is_some() {
        return Err("--generic-trap requires --snmp-version 1".to_string());
    }
    if v1_trap.specific_trap.is_some() {
        return Err("--specific-trap requires --snmp-version 1".to_string());
    }
    if v1_trap.timestamp.is_some() {
        return Err("--timestamp requires --snmp-version 1".to_string());
    }
    Ok(())
}

/// Fails fast when an inform is requested over SNMPv1
/// (common.py:validate_inform_version).
pub fn validate_inform_version(snmp_version: &str) -> Result<(), String> {
    if snmp_version == "1" {
        return Err("SNMPv1 has no inform operations — use trap".to_string());
    }
    Ok(())
}

/// Parses repeated CLI notification varbind specifications
/// (common.py:parse_notification_varbinds). Varbind OIDs are resolved eagerly
/// to numeric targets so symbolic-resolution failures surface before the
/// network connect, like the reference.
pub fn parse_notification_varbinds(
    values: &[String],
    bundle: Option<&MibBundle>,
) -> Result<Vec<(Target, SnmpValue)>, String> {
    values
        .iter()
        .map(|value| parse_notification_varbind(value, bundle))
        .collect()
}

/// Parses a single `OID=TYPE:VALUE` notification varbind specification
/// (common.py:parse_notification_varbind).
pub fn parse_notification_varbind(
    value: &str,
    bundle: Option<&MibBundle>,
) -> Result<(Target, SnmpValue), String> {
    let (oid_text, sep, value_spec) = partition_once(value, '=');
    let oid_target = oid_text.trim();
    if sep.is_empty() || oid_target.is_empty() {
        return Err(format!("Varbind must use OID=TYPE:VALUE form: {value}"));
    }
    let target = resolve_oid_target(oid_target, bundle)?;
    let snmp_value = parse_snmp_value(value_spec.trim(), bundle)?;
    Ok((Target::Numeric(target), snmp_value))
}

/// Parses a typed CLI value specification (common.py:parse_snmp_value).
pub fn parse_snmp_value(value: &str, bundle: Option<&MibBundle>) -> Result<SnmpValue, String> {
    let (type_name, sep, raw_value) = partition_once(value, ':');
    let normalized_type = type_name.trim().to_lowercase();
    if normalized_type.is_empty() {
        return Err(format!("Value type cannot be empty: {value}"));
    }
    if normalized_type == "null" {
        if !sep.is_empty() && !raw_value.trim().is_empty() {
            return Err("null values must not include a payload".to_string());
        }
        return Ok(SnmpValue::Null);
    }
    if sep.is_empty() {
        return Err(format!("Value must use TYPE:VALUE form: {value}"));
    }
    match normalized_type.as_str() {
        "int" | "integer" => Ok(SnmpValue::Integer(parse_int(raw_value, "integer")?)),
        // The reference encodes the raw (untrimmed) payload for str/string.
        "str" | "string" => Ok(SnmpValue::OctetString(raw_value.as_bytes().to_vec())),
        "hex" => Ok(SnmpValue::OctetString(parse_hex_bytes(raw_value)?)),
        "oid" => Ok(SnmpValue::ObjectIdentifier(resolve_oid_target(
            raw_value.trim(),
            bundle,
        )?)),
        "ip" | "ip-address" => {
            let addr = Ipv4Addr::from_str(raw_value.trim())
                .map_err(|_| format!("Invalid IP address: {value}"))?;
            Ok(SnmpValue::IpAddress(addr))
        }
        "counter32" => Ok(SnmpValue::Counter32(parse_non_negative_u32(
            raw_value,
            "counter32",
        )?)),
        "gauge32" => Ok(SnmpValue::Gauge32(parse_non_negative_u32(
            raw_value, "gauge32",
        )?)),
        "timeticks" => Ok(SnmpValue::TimeTicks(parse_non_negative_u32(
            raw_value,
            "timeticks",
        )?)),
        "opaque" => Ok(SnmpValue::Opaque(parse_hex_bytes(raw_value)?)),
        "counter64" => Ok(SnmpValue::Counter64(parse_non_negative_u64(
            raw_value,
            "counter64",
        )?)),
        _ => Err(format!("Unsupported value type: {}", type_name.trim())),
    }
}

/// Resolves a numeric or symbolic OID target for CLI inputs
/// (common.py:resolve_oid_target).
pub fn resolve_oid_target(target: &str, bundle: Option<&MibBundle>) -> Result<Oid, String> {
    if target.contains("::") {
        let bundle = bundle.ok_or_else(|| format!("Symbolic OID requires --bundle: {target}"))?;
        let parsed = Target::from_str(target).map_err(|e| e.to_string())?;
        bundle.resolve(&parsed).map_err(|e| e.to_string())
    } else {
        Oid::parse(target).map_err(|e| e.to_string())
    }
}

/// Parses raw hex bytes while tolerating common separators
/// (common.py:parse_hex_bytes).
pub fn parse_hex_bytes(value: &str) -> Result<Vec<u8>, String> {
    let mut normalized = value.trim().to_string();
    if let Some(rest) = normalized.strip_prefix("0x") {
        normalized = rest.to_string();
    }
    for separator in [' ', '\n', '\t', ':', '-'] {
        normalized = normalized.replace(separator, "");
    }
    if !normalized.len().is_multiple_of(2) {
        return Err(format!(
            "Hex payload must contain an even number of digits: {value}"
        ));
    }
    (0..normalized.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&normalized[i..i + 2], 16)
                .map_err(|_| format!("Invalid hex payload: {value}"))
        })
        .collect()
}

/// The v3 user parse + key validation (common.py:_parse_v3_user).
fn parse_v3_user(usm: &UsmArgs) -> Result<UsmUser, String> {
    let username = usm
        .username
        .clone()
        .ok_or("--username is required with --snmp-version 3")?;
    let auth_protocol = parse_auth_protocol(&usm.auth_protocol)?;
    let priv_protocol = parse_priv_protocol(&usm.priv_protocol)?;
    let auth_key = resolve_secret(&usm.auth_key, &usm.auth_key_env, "auth")?;
    let priv_key = resolve_secret(&usm.priv_key, &usm.priv_key_env, "priv")?;

    if auth_protocol == AuthProtocol::None_ {
        if auth_key.is_some() {
            return Err(
                "--auth-key and --auth-key-env require --auth-protocol to be md5, sha1, sha224, sha256, sha384, or sha512"
                    .to_string(),
            );
        }
    } else if auth_key.is_none() {
        return Err("SNMPv3 auth requires exactly one of --auth-key or --auth-key-env".to_string());
    }

    if priv_protocol == PrivProtocol::None_ {
        if priv_key.is_some() {
            return Err(
                "--priv-key and --priv-key-env require --priv-protocol to be aes128, aes192, aes256, or 3des-ede"
                    .to_string(),
            );
        }
    } else {
        if auth_protocol == AuthProtocol::None_ {
            return Err("--priv-protocol requires --auth-protocol to be enabled".to_string());
        }
        if priv_key.is_none() {
            return Err(
                "SNMPv3 privacy requires exactly one of --priv-key or --priv-key-env".to_string(),
            );
        }
    }

    UsmUser::new(
        username,
        auth_protocol,
        AuthKey::Passphrase(auth_key.unwrap_or_default()),
        priv_protocol,
        PrivKey::Passphrase(priv_key.unwrap_or_default()),
    )
    .map_err(|e| e.to_string())
}

/// The v1/v2c security parse with every v3-flag rejection
/// (common.py:_parse_community_cli_security).
fn parse_community_cli_security(
    security: &SecurityArgs,
    context_name: &str,
    local_engine: &impl HasLocalEngine,
) -> Result<String, String> {
    let version = &security.snmp_version;
    reject_community_usm_flags(&security.usm, version)?;
    if !context_name.is_empty() {
        return Err(format!(
            "--context-name is invalid with --snmp-version {version}"
        ));
    }
    if local_engine_supplied(local_engine) {
        return Err(format!(
            "--local-engine-* options are invalid with --snmp-version {version}"
        ));
    }
    Ok(security
        .community
        .clone()
        .unwrap_or_else(|| "public".to_string()))
}

/// The v3-flag-with-community-version rejections shared by the manager,
/// listener, and decode paths (common.py `_parse_community_cli_security` /
/// `parse_listener_cli_security` / `parse_decode_notification_user`).
fn reject_community_usm_flags(usm: &UsmArgs, version: &str) -> Result<(), String> {
    if usm.username.is_some() {
        return Err(format!(
            "--username is invalid with --snmp-version {version}"
        ));
    }
    if usm.auth_protocol != "none" {
        return Err(format!(
            "--auth-protocol is invalid with --snmp-version {version}"
        ));
    }
    if usm.auth_key.is_some() || usm.auth_key_env.is_some() {
        return Err(format!(
            "--auth-key and --auth-key-env are invalid with --snmp-version {version}"
        ));
    }
    if usm.priv_protocol != "none" {
        return Err(format!(
            "--priv-protocol is invalid with --snmp-version {version}"
        ));
    }
    if usm.priv_key.is_some() || usm.priv_key_env.is_some() {
        return Err(format!(
            "--priv-key and --priv-key-env are invalid with --snmp-version {version}"
        ));
    }
    Ok(())
}

/// Resolves a secret from the inline flag or the named environment variable
/// (common.py:_resolve_secret). The user names the variable: `--auth-key-env
/// TSNMP_AUTH` reads the passphrase from `$TSNMP_AUTH`.
fn resolve_secret(
    inline: &Option<String>,
    env_name: &Option<String>,
    label: &str,
) -> Result<Option<Vec<u8>>, String> {
    let flag = if label == "auth" {
        "auth-key"
    } else {
        "priv-key"
    };
    match (inline, env_name) {
        (Some(_), Some(_)) => Err(format!("Use only one of --{flag} or --{flag}-env")),
        (Some(value), None) => Ok(Some(value.clone().into_bytes())),
        (None, Some(var)) => match std::env::var(var) {
            Ok(value) => Ok(Some(value.into_bytes())),
            Err(_) => Err(format!(
                "Environment variable {var} is not set for SNMPv3 {label} credentials"
            )),
        },
        (None, None) => Ok(None),
    }
}

/// The local-engine parse (common.py:_parse_local_engine). The usage string is
/// "trap" for the live notifier path and "listener" for the listen command.
fn parse_local_engine(
    args: &impl HasLocalEngine,
    required: bool,
    allowed: bool,
    usage: &str,
) -> Result<Option<UsmLocalEngine>, String> {
    let supplied = local_engine_supplied(args);
    if supplied && !allowed {
        return Err(format!(
            "--local-engine-* options are only valid for SNMPv3 {usage}"
        ));
    }
    if !supplied {
        if required {
            return Err(format!(
                "SNMPv3 {usage} requires --local-engine-id, --local-engine-boots, and --local-engine-time"
            ));
        }
        return Ok(None);
    }
    let Some(engine_id) = args.local_engine_id() else {
        return Err(format!("SNMPv3 {usage} requires --local-engine-id"));
    };
    let Some(engine_boots) = args.local_engine_boots() else {
        return Err(format!("SNMPv3 {usage} requires --local-engine-boots"));
    };
    let Some(engine_time) = args.local_engine_time() else {
        return Err(format!("SNMPv3 {usage} requires --local-engine-time"));
    };
    if engine_boots < 0 {
        return Err("--local-engine-boots cannot be negative".to_string());
    }
    if engine_time < 0 {
        return Err("--local-engine-time cannot be negative".to_string());
    }
    let engine_id = parse_hex_bytes(engine_id)?;
    if engine_id.is_empty() {
        return Err("--local-engine-id cannot be empty".to_string());
    }
    Ok(Some(UsmLocalEngine {
        engine_id,
        engine_boots: engine_boots as u32,
        engine_time: engine_time as u32,
    }))
}

fn local_engine_supplied(args: &impl HasLocalEngine) -> bool {
    args.local_engine_id().is_some()
        || args.local_engine_boots().is_some()
        || args.local_engine_time().is_some()
}

/// Maps the reference's `_parse_int`.
fn parse_int(value: &str, field: &str) -> Result<i64, String> {
    value
        .trim()
        .parse::<i64>()
        .map_err(|_| format!("Invalid {field} value: {value}"))
}

/// Maps the reference's `_parse_non_negative_int` for u32 fields. Values the
/// u32 type cannot hold fail here (the reference's dataclasses accept them and
/// fail at encode; the typed `SnmpValue` enum cannot represent them — §8).
fn parse_non_negative_u32(value: &str, field: &str) -> Result<u32, String> {
    let parsed = value
        .trim()
        .parse::<i64>()
        .map_err(|_| format!("Invalid {field} value: {value}"))?;
    if parsed < 0 {
        return Err(format!("{field} cannot be negative: {value}"));
    }
    u32::try_from(parsed).map_err(|_| format!("{field} value out of range: {value}"))
}

/// Maps the reference's `_parse_non_negative_int` for the u64 counter64 field.
fn parse_non_negative_u64(value: &str, field: &str) -> Result<u64, String> {
    match value.trim().parse::<i64>() {
        Ok(parsed) if parsed < 0 => Err(format!("{field} cannot be negative: {value}")),
        Ok(parsed) => Ok(parsed as u64),
        Err(_) => value
            .trim()
            .parse::<u64>()
            .map_err(|_| format!("Invalid {field} value: {value}")),
    }
}

fn parse_auth_protocol(value: &str) -> Result<AuthProtocol, String> {
    match value {
        "none" => Ok(AuthProtocol::None_),
        "md5" => Ok(AuthProtocol::Md5),
        "sha1" => Ok(AuthProtocol::Sha1),
        "sha224" => Ok(AuthProtocol::Sha224),
        "sha256" => Ok(AuthProtocol::Sha256),
        "sha384" => Ok(AuthProtocol::Sha384),
        "sha512" => Ok(AuthProtocol::Sha512),
        _ => Err(format!("Unsupported auth protocol: {value}")),
    }
}

fn parse_priv_protocol(value: &str) -> Result<PrivProtocol, String> {
    match value {
        "none" => Ok(PrivProtocol::None_),
        "des" => Err(
            "DES-CBC privacy is unavailable: tsnmp locks DES-CBC out; use aes128, aes192, aes256, or 3des-ede"
                .to_string(),
        ),
        "aes128" => Ok(PrivProtocol::Aes128),
        "aes192" => Ok(PrivProtocol::Aes192),
        "aes256" => Ok(PrivProtocol::Aes256),
        "3des-ede" => Ok(PrivProtocol::Des3Ede),
        _ => Err(format!("Unsupported privacy protocol: {value}")),
    }
}

/// Splits `text` at the first `separator`, returning the parts (an empty
/// separator marker means it was absent, mirroring Python's `partition`).
fn partition_once(text: &str, separator: char) -> (&str, &str, &str) {
    match text.find(separator) {
        Some(index) => (
            &text[..index],
            &text[index..index + separator.len_utf8()],
            &text[index + separator.len_utf8()..],
        ),
        None => (text, "", ""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn security_args() -> SecurityArgs {
        SecurityArgs {
            snmp_version: "2c".to_string(),
            community: None,
            ..SecurityArgs::default()
        }
    }

    fn listener_security_args() -> (String, Vec<String>, UsmArgs, LocalEngineArgs) {
        (
            "2c".to_string(),
            Vec::new(),
            UsmArgs::default(),
            LocalEngineArgs::default(),
        )
    }

    #[test]
    fn parse_cli_security_defaults_to_v2c_public() {
        let parsed = parse_cli_security(
            &security_args(),
            "",
            false,
            false,
            &LocalEngineArgs::default(),
        )
        .unwrap();
        match parsed {
            CliSecurity::Community { community, version } => {
                assert_eq!(community, "public");
                assert_eq!(version, "2c");
            }
            CliSecurity::V3 { .. } => panic!("expected community security"),
        }
    }

    #[test]
    fn parse_cli_security_builds_v3_noauthnopriv() {
        let mut security = security_args();
        security.snmp_version = "3".to_string();
        security.usm.username = Some("alice".to_string());
        let parsed = parse_cli_security(
            &security,
            "alerts",
            false,
            false,
            &LocalEngineArgs::default(),
        )
        .unwrap();
        match parsed {
            CliSecurity::V3 {
                user,
                context_name,
                local_engine,
            } => {
                assert_eq!(user.username, "alice");
                assert_eq!(user.auth_protocol, AuthProtocol::None_);
                assert_eq!(user.priv_protocol, PrivProtocol::None_);
                assert_eq!(context_name, b"alerts");
                assert!(local_engine.is_none());
            }
            CliSecurity::Community { .. } => panic!("expected v3 security"),
        }
    }

    #[test]
    fn parse_cli_security_builds_v3_authpriv_from_env() {
        static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: guarded by ENV_LOCK; edition-2024 set_var is unsafe.
        unsafe {
            std::env::set_var("TSNMP_AUTH", "auth-secret");
            std::env::set_var("TSNMP_PRIV", "priv-secret");
        }
        let mut security = security_args();
        security.snmp_version = "3".to_string();
        security.usm.username = Some("alice".to_string());
        security.usm.auth_protocol = "sha256".to_string();
        security.usm.auth_key_env = Some("TSNMP_AUTH".to_string());
        security.usm.priv_protocol = "aes128".to_string();
        security.usm.priv_key_env = Some("TSNMP_PRIV".to_string());
        let parsed =
            parse_cli_security(&security, "", false, false, &LocalEngineArgs::default()).unwrap();
        match parsed {
            CliSecurity::V3 { user, .. } => {
                assert_eq!(user.auth_protocol, AuthProtocol::Sha256);
                assert_eq!(user.auth_key, AuthKey::Passphrase(b"auth-secret".to_vec()));
                assert_eq!(user.priv_protocol, PrivProtocol::Aes128);
                assert_eq!(user.priv_key, PrivKey::Passphrase(b"priv-secret".to_vec()));
            }
            CliSecurity::Community { .. } => panic!("expected v3 security"),
        }
        // SAFETY: guarded by ENV_LOCK.
        unsafe {
            std::env::remove_var("TSNMP_AUTH");
            std::env::remove_var("TSNMP_PRIV");
        }
    }

    #[test]
    fn parse_cli_security_rejects_v3_with_community() {
        let mut security = security_args();
        security.snmp_version = "3".to_string();
        security.community = Some("public".to_string());
        security.usm.username = Some("alice".to_string());
        let err = parse_cli_security(&security, "", false, false, &LocalEngineArgs::default())
            .unwrap_err();
        assert_eq!(err, "--community is invalid with --snmp-version 3");
    }

    #[test]
    fn parse_cli_security_rejects_missing_auth_key() {
        let mut security = security_args();
        security.snmp_version = "3".to_string();
        security.usm.username = Some("alice".to_string());
        security.usm.auth_protocol = "md5".to_string();
        let err = parse_cli_security(&security, "", false, false, &LocalEngineArgs::default())
            .unwrap_err();
        assert!(
            err.contains("exactly one of --auth-key or --auth-key-env"),
            "{err}"
        );
    }

    #[test]
    fn parse_cli_security_rejects_priv_without_auth() {
        let mut security = security_args();
        security.snmp_version = "3".to_string();
        security.usm.username = Some("alice".to_string());
        security.usm.priv_protocol = "aes128".to_string();
        security.usm.priv_key = Some("secret".to_string());
        let err = parse_cli_security(&security, "", false, false, &LocalEngineArgs::default())
            .unwrap_err();
        assert_eq!(
            err,
            "--priv-protocol requires --auth-protocol to be enabled"
        );
    }

    #[test]
    fn parse_cli_security_requires_local_engine_for_v3_trap() {
        let mut security = security_args();
        security.snmp_version = "3".to_string();
        security.usm.username = Some("alice".to_string());
        let err =
            parse_cli_security(&security, "", true, true, &LocalEngineArgs::default()).unwrap_err();
        assert!(
            err.contains("SNMPv3 trap requires --local-engine-id"),
            "{err}"
        );
    }

    #[test]
    fn parse_cli_security_builds_v3_local_engine_for_trap() {
        let mut security = security_args();
        security.snmp_version = "3".to_string();
        security.usm.username = Some("alice".to_string());
        let local_engine = LocalEngineArgs {
            local_engine_id: Some("80:00:01:02:03".to_string()),
            local_engine_boots: Some(7),
            local_engine_time: Some(99),
        };
        let parsed = parse_cli_security(&security, "", true, true, &local_engine).unwrap();
        match parsed {
            CliSecurity::V3 { local_engine, .. } => {
                let engine = local_engine.expect("required");
                assert_eq!(engine.engine_id, vec![0x80, 0x00, 0x01, 0x02, 0x03]);
                assert_eq!(engine.engine_boots, 7);
                assert_eq!(engine.engine_time, 99);
            }
            CliSecurity::Community { .. } => panic!("expected v3 security"),
        }
    }

    #[test]
    fn parse_cli_security_rejects_local_engine_when_not_allowed() {
        let mut security = security_args();
        security.snmp_version = "3".to_string();
        security.usm.username = Some("alice".to_string());
        let local_engine = LocalEngineArgs {
            local_engine_id: Some("8000010203".to_string()),
            local_engine_boots: Some(1),
            local_engine_time: Some(2),
        };
        let err = parse_cli_security(&security, "", false, false, &local_engine).unwrap_err();
        assert_eq!(
            err,
            "--local-engine-* options are only valid for SNMPv3 trap"
        );
    }

    #[test]
    fn parse_cli_security_rejects_missing_env_secret() {
        static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: guarded by ENV_LOCK.
        unsafe {
            std::env::remove_var("TSNMP_AUTH");
        }
        let mut security = security_args();
        security.snmp_version = "3".to_string();
        security.usm.username = Some("alice".to_string());
        security.usm.auth_protocol = "sha1".to_string();
        security.usm.auth_key_env = Some("TSNMP_AUTH".to_string());
        let err = parse_cli_security(&security, "", false, false, &LocalEngineArgs::default())
            .unwrap_err();
        assert_eq!(
            err,
            "Environment variable TSNMP_AUTH is not set for SNMPv3 auth credentials"
        );
    }

    #[test]
    fn parse_cli_security_builds_v1_community() {
        let mut security = security_args();
        security.snmp_version = "1".to_string();
        security.community = Some("private".to_string());
        let parsed =
            parse_cli_security(&security, "", false, false, &LocalEngineArgs::default()).unwrap();
        match parsed {
            CliSecurity::Community { community, version } => {
                assert_eq!(community, "private");
                assert_eq!(version, "1");
            }
            CliSecurity::V3 { .. } => panic!("expected community security"),
        }
    }

    #[test]
    fn parse_cli_security_rejects_v3_flags_with_v1() {
        let mut security = security_args();
        security.snmp_version = "1".to_string();
        security.usm.username = Some("alice".to_string());
        let err = parse_cli_security(&security, "", false, false, &LocalEngineArgs::default())
            .unwrap_err();
        assert_eq!(err, "--username is invalid with --snmp-version 1");

        let mut security = security_args();
        security.snmp_version = "1".to_string();
        let err = parse_cli_security(
            &security,
            "alerts",
            false,
            false,
            &LocalEngineArgs::default(),
        )
        .unwrap_err();
        assert_eq!(err, "--context-name is invalid with --snmp-version 1");

        let mut security = security_args();
        security.snmp_version = "1".to_string();
        let local_engine = LocalEngineArgs {
            local_engine_id: Some("8000010203".to_string()),
            local_engine_boots: Some(1),
            local_engine_time: Some(2),
        };
        let err = parse_cli_security(&security, "", false, false, &local_engine).unwrap_err();
        assert_eq!(
            err,
            "--local-engine-* options are invalid with --snmp-version 1"
        );
    }

    #[test]
    fn parse_listener_cli_security_accepts_v1_community_listener() {
        let (version, communities, usm, local_engine) = listener_security_args();
        let parsed =
            parse_listener_cli_security(&version, &["public".to_string()], &usm, &local_engine)
                .unwrap();
        match parsed {
            ListenerCliSecurity::Community { communities } => {
                assert_eq!(communities, Some(vec!["public".to_string()]));
            }
            ListenerCliSecurity::V3 { .. } => panic!("expected community listener"),
        }
        let _ = communities;
    }

    #[test]
    fn parse_listener_cli_security_rejects_v3_flags_with_v1() {
        let (_version, communities, mut usm, local_engine) = listener_security_args();
        usm.auth_protocol = "md5".to_string();
        let err = parse_listener_cli_security("1", &communities, &usm, &local_engine).unwrap_err();
        assert_eq!(err, "--auth-protocol is invalid with --snmp-version 1");
    }

    #[test]
    fn parse_listener_cli_security_defaults_to_v2c() {
        let (version, communities, usm, local_engine) = listener_security_args();
        let parsed =
            parse_listener_cli_security(&version, &communities, &usm, &local_engine).unwrap();
        match parsed {
            ListenerCliSecurity::Community { communities } => assert!(communities.is_none()),
            ListenerCliSecurity::V3 { .. } => panic!("expected community listener"),
        }
    }

    #[test]
    fn parse_listener_cli_security_builds_v3_listener() {
        let (_version, communities, mut usm, _local_engine) = listener_security_args();
        let _ = &mut usm;
        let local_engine = LocalEngineArgs {
            local_engine_id: Some("80:00:01:02:03".to_string()),
            local_engine_boots: Some(7),
            local_engine_time: Some(99),
        };
        usm.username = Some("alice".to_string());
        let parsed = parse_listener_cli_security("3", &communities, &usm, &local_engine).unwrap();
        match parsed {
            ListenerCliSecurity::V3 { user, local_engine } => {
                assert_eq!(user.username, "alice");
                assert_eq!(local_engine.engine_id, vec![0x80, 0x00, 0x01, 0x02, 0x03]);
            }
            ListenerCliSecurity::Community { .. } => panic!("expected v3 listener"),
        }
    }

    #[test]
    fn parse_listener_cli_security_requires_local_engine() {
        let usm = UsmArgs {
            username: Some("alice".to_string()),
            ..UsmArgs::default()
        };
        let err =
            parse_listener_cli_security("3", &[], &usm, &LocalEngineArgs::default()).unwrap_err();
        assert!(
            err.contains("SNMPv3 listener requires --local-engine-id"),
            "{err}"
        );
    }

    #[test]
    fn parse_listener_cli_security_rejects_community_on_v3() {
        let (_version, _communities, mut usm, local_engine) = listener_security_args();
        usm.username = Some("alice".to_string());
        let err = parse_listener_cli_security("3", &["public".to_string()], &usm, &local_engine)
            .unwrap_err();
        assert_eq!(err, "--community is invalid with --snmp-version 3");
    }

    #[test]
    fn parse_decode_notification_user_builds_v3_user() {
        let usm = UsmArgs {
            username: Some("alice".to_string()),
            auth_protocol: "md5".to_string(),
            auth_key: Some("secret".to_string()),
            ..UsmArgs::default()
        };
        let user = parse_decode_notification_user("3", &usm)
            .unwrap()
            .expect("v3 user");
        assert_eq!(user.username, "alice");
        assert_eq!(user.auth_protocol, AuthProtocol::Md5);
        assert_eq!(user.auth_key, AuthKey::Passphrase(b"secret".to_vec()));
    }

    #[test]
    fn parse_decode_notification_user_rejects_v2c_with_v3_args() {
        let usm = UsmArgs {
            username: Some("alice".to_string()),
            ..UsmArgs::default()
        };
        let err = parse_decode_notification_user("2c", &usm).unwrap_err();
        assert_eq!(err, "--username is invalid with --snmp-version 2c");
    }

    #[test]
    fn parse_decode_notification_user_defaults_to_v2c() {
        assert!(
            parse_decode_notification_user("2c", &UsmArgs::default())
                .unwrap()
                .is_none()
        );
    }

    fn trap_args() -> (String, Option<String>, u32, V1TrapArgs) {
        (
            "2c".to_string(),
            Some("1.3.6.1.6.3.1.1.5.3".to_string()),
            0,
            V1TrapArgs::default(),
        )
    }

    #[test]
    fn validate_trap_version_flags_passes_v1_with_enterprise() {
        let v1 = V1TrapArgs {
            enterprise: Some("1.3.6.1.4.1.999".to_string()),
            ..V1TrapArgs::default()
        };
        validate_trap_version_flags("1", &None, 0, &v1).unwrap();
    }

    #[test]
    fn validate_trap_version_flags_rejects_v1_without_enterprise() {
        let err = validate_trap_version_flags("1", &None, 0, &V1TrapArgs::default()).unwrap_err();
        assert_eq!(err, "--enterprise is required with --snmp-version 1");
    }

    #[test]
    fn validate_trap_version_flags_rejects_v1_positional_target() {
        let v1 = V1TrapArgs {
            enterprise: Some("1.3.6.1.4.1.999".to_string()),
            ..V1TrapArgs::default()
        };
        let (version, notification, uptime, _) = trap_args();
        let err = validate_trap_version_flags(&version, &notification, uptime, &v1).unwrap_err();
        // v2c with --enterprise.
        assert_eq!(err, "--enterprise requires --snmp-version 1");
        // v1 with a positional target.
        let err =
            validate_trap_version_flags("1", &Some("1.3.6.1.6.3.1.1.5.3".to_string()), 0, &v1)
                .unwrap_err();
        assert_eq!(
            err,
            "a positional notification OID is invalid with --snmp-version 1; use --enterprise"
        );
    }

    #[test]
    fn validate_trap_version_flags_rejects_v1_uptime() {
        let v1 = V1TrapArgs {
            enterprise: Some("1.3.6.1.4.1.999".to_string()),
            ..V1TrapArgs::default()
        };
        let err = validate_trap_version_flags("1", &None, 55, &v1).unwrap_err();
        assert_eq!(
            err,
            "--uptime is invalid with --snmp-version 1; use --timestamp"
        );
    }

    #[test]
    fn validate_trap_version_flags_rejects_v1_flags_with_v2c() {
        for (flag, name) in [
            ("enterprise", "--enterprise"),
            ("agent_addr", "--agent-addr"),
            ("generic_trap", "--generic-trap"),
            ("specific_trap", "--specific-trap"),
            ("timestamp", "--timestamp"),
        ] {
            let mut v1 = V1TrapArgs::default();
            match flag {
                "enterprise" => v1.enterprise = Some("1".to_string()),
                "agent_addr" => v1.agent_addr = Some("0.0.0.0".to_string()),
                "generic_trap" => v1.generic_trap = Some(1),
                "specific_trap" => v1.specific_trap = Some(1),
                "timestamp" => v1.timestamp = Some(1),
                _ => unreachable!(),
            }
            let err = validate_trap_version_flags("2c", &Some("1.3.6.1".to_string()), 0, &v1)
                .unwrap_err();
            assert_eq!(err, format!("{name} requires --snmp-version 1"));
        }
    }

    #[test]
    fn validate_inform_version_passes_for_v2c_and_v3() {
        validate_inform_version("2c").unwrap();
        validate_inform_version("3").unwrap();
    }

    #[test]
    fn validate_inform_version_rejects_v1() {
        let err = validate_inform_version("1").unwrap_err();
        assert_eq!(err, "SNMPv1 has no inform operations — use trap");
    }

    #[test]
    fn parse_notification_varbinds_empty_returns_empty() {
        assert!(parse_notification_varbinds(&[], None).unwrap().is_empty());
    }

    #[test]
    fn parse_notification_varbind_rejects_invalid_shape() {
        let err = parse_notification_varbind("IF-MIB::ifDescr.1", None).unwrap_err();
        assert!(err.contains("OID=TYPE:VALUE"), "{err}");
        let err = parse_notification_varbind("=int:1", None).unwrap_err();
        assert!(err.contains("OID=TYPE:VALUE"), "{err}");
    }

    #[test]
    fn parse_snmp_value_supports_expected_types() {
        assert_eq!(parse_snmp_value("null", None).unwrap(), SnmpValue::Null);
        assert_eq!(
            parse_snmp_value("integer:-7", None).unwrap(),
            SnmpValue::Integer(-7)
        );
        assert_eq!(
            parse_snmp_value("string:eth0", None).unwrap(),
            SnmpValue::OctetString(b"eth0".to_vec())
        );
        assert_eq!(
            parse_snmp_value("hex:61:62-63 64", None).unwrap(),
            SnmpValue::OctetString(b"abcd".to_vec())
        );
        assert_eq!(
            parse_snmp_value("ip-address:192.0.2.1", None).unwrap(),
            SnmpValue::IpAddress("192.0.2.1".parse().unwrap())
        );
        assert_eq!(
            parse_snmp_value("counter32:7", None).unwrap(),
            SnmpValue::Counter32(7)
        );
        assert_eq!(
            parse_snmp_value("gauge32:8", None).unwrap(),
            SnmpValue::Gauge32(8)
        );
        assert_eq!(
            parse_snmp_value("timeticks:9", None).unwrap(),
            SnmpValue::TimeTicks(9)
        );
        assert_eq!(
            parse_snmp_value("opaque:aa bb", None).unwrap(),
            SnmpValue::Opaque(vec![0xaa, 0xbb])
        );
        assert_eq!(
            parse_snmp_value("counter64:10", None).unwrap(),
            SnmpValue::Counter64(10)
        );
        assert_eq!(
            parse_snmp_value("oid:1.3.6.1.2.1", None).unwrap(),
            SnmpValue::ObjectIdentifier(Oid::from_arcs(&[1, 3, 6, 1, 2, 1]).unwrap())
        );
    }

    #[test]
    fn parse_snmp_value_rejects_invalid_forms() {
        let err = parse_snmp_value(":7", None).unwrap_err();
        assert!(err.contains("Value type cannot be empty"), "{err}");
        let err = parse_snmp_value("null:1", None).unwrap_err();
        assert!(
            err.contains("null values must not include a payload"),
            "{err}"
        );
        let err = parse_snmp_value("integer", None).unwrap_err();
        assert!(err.contains("TYPE:VALUE"), "{err}");
        let err = parse_snmp_value("unknown:1", None).unwrap_err();
        assert!(err.contains("Unsupported value type"), "{err}");
        let err = parse_snmp_value("integer:nope", None).unwrap_err();
        assert!(err.contains("Invalid integer value"), "{err}");
        let err = parse_snmp_value("counter32:-1", None).unwrap_err();
        assert!(err.contains("counter32 cannot be negative"), "{err}");
        let err = parse_snmp_value("opaque:zz", None).unwrap_err();
        assert!(err.contains("Invalid hex payload"), "{err}");
        let err = parse_snmp_value("oid:IF-MIB::ifDescr.1", None).unwrap_err();
        assert!(err.contains("Symbolic OID requires --bundle"), "{err}");
    }

    #[test]
    fn parse_hex_bytes_rejects_odd_and_invalid_payloads() {
        let err = parse_hex_bytes("abc").unwrap_err();
        assert!(err.contains("even number of digits"), "{err}");
        let err = parse_hex_bytes("zz").unwrap_err();
        assert!(err.contains("Invalid hex payload"), "{err}");
        assert_eq!(parse_hex_bytes("0x616263"), Ok(b"abc".to_vec()));
        assert_eq!(parse_hex_bytes("61 62:63-64"), Ok(b"abcd".to_vec()));
    }

    #[test]
    fn parse_cli_security_supports_sha2_auth_choices() {
        for (choice, protocol) in [
            ("sha224", AuthProtocol::Sha224),
            ("sha384", AuthProtocol::Sha384),
            ("sha512", AuthProtocol::Sha512),
        ] {
            let mut security = security_args();
            security.snmp_version = "3".to_string();
            security.usm.username = Some("alice".to_string());
            security.usm.auth_protocol = choice.to_string();
            security.usm.auth_key = Some("secret".to_string());
            let parsed =
                parse_cli_security(&security, "", false, false, &LocalEngineArgs::default())
                    .unwrap();
            match parsed {
                CliSecurity::V3 { user, .. } => assert_eq!(user.auth_protocol, protocol),
                CliSecurity::Community { .. } => panic!("expected v3 security"),
            }
        }
    }

    #[test]
    fn parse_cli_security_supports_reeder_priv_choices() {
        for (choice, protocol) in [
            ("aes192", PrivProtocol::Aes192),
            ("aes256", PrivProtocol::Aes256),
            ("3des-ede", PrivProtocol::Des3Ede),
        ] {
            let mut security = security_args();
            security.snmp_version = "3".to_string();
            security.usm.username = Some("alice".to_string());
            security.usm.auth_protocol = "md5".to_string();
            security.usm.auth_key = Some("secret".to_string());
            security.usm.priv_protocol = choice.to_string();
            security.usm.priv_key = Some("priv-secret".to_string());
            let parsed =
                parse_cli_security(&security, "", false, false, &LocalEngineArgs::default())
                    .unwrap();
            match parsed {
                CliSecurity::V3 { user, .. } => assert_eq!(user.priv_protocol, protocol),
                CliSecurity::Community { .. } => panic!("expected v3 security"),
            }
        }
    }

    #[test]
    fn parse_cli_security_rejects_des_priv_at_cli_level() {
        let mut security = security_args();
        security.snmp_version = "3".to_string();
        security.usm.username = Some("alice".to_string());
        security.usm.auth_protocol = "md5".to_string();
        security.usm.auth_key = Some("secret".to_string());
        security.usm.priv_protocol = "des".to_string();
        security.usm.priv_key = Some("priv-secret".to_string());
        let err = parse_cli_security(&security, "", false, false, &LocalEngineArgs::default())
            .unwrap_err();
        assert!(err.contains("DES-CBC privacy is unavailable"), "{err}");
    }

    #[test]
    fn parse_cli_security_rejects_both_inline_and_env_secret() {
        let mut security = security_args();
        security.snmp_version = "3".to_string();
        security.usm.username = Some("alice".to_string());
        security.usm.auth_protocol = "md5".to_string();
        security.usm.auth_key = Some("inline".to_string());
        security.usm.auth_key_env = Some("TSNMP_AUTH".to_string());
        let err = parse_cli_security(&security, "", false, false, &LocalEngineArgs::default())
            .unwrap_err();
        assert_eq!(err, "Use only one of --auth-key or --auth-key-env");
    }

    #[test]
    fn parse_local_engine_rejects_negative_fields() {
        let mut security = security_args();
        security.snmp_version = "3".to_string();
        security.usm.username = Some("alice".to_string());
        let local_engine = LocalEngineArgs {
            local_engine_id: Some("8000010203".to_string()),
            local_engine_boots: Some(-1),
            local_engine_time: Some(2),
        };
        let err = parse_cli_security(&security, "", true, true, &local_engine).unwrap_err();
        assert_eq!(err, "--local-engine-boots cannot be negative");

        let local_engine = LocalEngineArgs {
            local_engine_id: Some("8000010203".to_string()),
            local_engine_boots: Some(1),
            local_engine_time: Some(-2),
        };
        let err = parse_cli_security(&security, "", true, true, &local_engine).unwrap_err();
        assert_eq!(err, "--local-engine-time cannot be negative");
    }
}
