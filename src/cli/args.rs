//! Clap definitions + env secrets (← cli/main.py + common.py)
//!
//! The 11 subcommands and every flag of the reference CLI, modeled with clap 4
//! derive. Flag-mixing validation is deliberately NOT expressed as clap
//! conflicts: the reference parses everything with argparse and validates in
//! `parse_cli_security`/`validate_trap_version_flags` (common.py), surfacing
//! `tsnmp: <message>` with exit code 1. Porting that behavior verbatim keeps
//! the pinned error strings and exit codes (docs/cli.md; §8 deviations); clap
//! stays permissive and `cli/common.rs` validates.
//!
//! `--auth-key-env`/`--priv-key-env` take a VARNAME: the passphrase is read
//! from that environment variable at validation time (`cli/common.rs`), not
//! by clap's own `env` feature (the variable name is a runtime value, not a
//! static attribute).

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// Modern SNMP manager runtime CLI with optional compiled-JSON MIB enrichment.
#[derive(Parser, Debug)]
#[command(name = "tsnmp", about, disable_version_flag = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// The 11 subcommands (plan.md Phase 8; cli/main.py:76–195).
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Translate numeric OIDs and symbolic names using a compiled bundle
    Translate(TranslateArgs),
    /// Perform an SNMP GET request
    Get(TargetsArgs),
    /// Perform an SNMP GETNEXT request
    #[command(name = "getnext")]
    GetNext(TargetsArgs),
    /// Perform an SNMP GETBULK request
    #[command(name = "getbulk")]
    GetBulk(BulkArgs),
    /// Walk an SNMP subtree
    Walk(WalkArgs),
    /// Walk an SNMP subtree using GETBULK
    #[command(name = "bulkwalk")]
    BulkWalk(BulkWalkArgs),
    /// Send an SNMP trap
    Trap(TrapArgs),
    /// Send an SNMP inform
    Inform(InformArgs),
    /// Listen for inbound SNMP notifications
    Listen(ListenArgs),
    /// Decode a BER-encoded SNMP trap or inform message
    #[command(name = "decode-notification")]
    DecodeNotification(DecodeArgs),
    /// Print the installed version
    Version,
}

/// SNMP version / community / USM options (common.py `_add_security_options`
/// minus `--context-name`, which the listener and decode commands do not
/// carry; minus the repeatable `--community`, which is listener-specific).
///
/// The manual `Default` mirrors the clap `default_value`s so unit tests
/// construct the same shape clap produces.
#[derive(Args, Debug, Clone)]
pub struct SecurityArgs {
    /// SNMP version for live operations (default: 2c)
    #[arg(
        long,
        default_value = "2c",
        value_parser = ["1", "2c", "3"]
    )]
    pub snmp_version: String,
    /// SNMPv1/v2c community string (default when omitted: public)
    #[arg(long)]
    pub community: Option<String>,
    #[command(flatten)]
    pub usm: UsmArgs,
}

impl Default for SecurityArgs {
    fn default() -> Self {
        Self {
            snmp_version: "2c".to_string(),
            community: None,
            usm: UsmArgs::default(),
        }
    }
}

/// The v3 USM options (common.py `_add_v3_usm_options`).
///
/// The manual `Default` mirrors the clap `default_value`s so unit tests
/// construct the same shape clap produces.
#[derive(Args, Debug, Clone)]
pub struct UsmArgs {
    /// SNMPv3 username
    #[arg(long)]
    pub username: Option<String>,
    /// SNMPv3 auth protocol (default: none)
    #[arg(
        long,
        default_value = "none",
        value_parser = ["none", "md5", "sha1", "sha224", "sha256", "sha384", "sha512"]
    )]
    pub auth_protocol: String,
    /// SNMPv3 auth passphrase
    #[arg(long)]
    pub auth_key: Option<String>,
    /// Environment variable holding the SNMPv3 auth key
    #[arg(long)]
    pub auth_key_env: Option<String>,
    /// SNMPv3 privacy protocol (default: none); `des` is accepted and then
    /// rejected at validation with the reference's exit-1 error
    #[arg(
        long,
        default_value = "none",
        value_parser = ["none", "des", "aes128", "aes192", "aes256", "3des-ede"]
    )]
    pub priv_protocol: String,
    /// SNMPv3 privacy passphrase
    #[arg(long)]
    pub priv_key: Option<String>,
    /// Environment variable holding the SNMPv3 priv key
    #[arg(long)]
    pub priv_key_env: Option<String>,
}

impl Default for UsmArgs {
    fn default() -> Self {
        Self {
            username: None,
            auth_protocol: "none".to_string(),
            auth_key: None,
            auth_key_env: None,
            priv_protocol: "none".to_string(),
            priv_key: None,
            priv_key_env: None,
        }
    }
}

/// The SNMPv3 sender-authoritative engine inputs for trap send flows
/// (common.py `add_local_engine_options`).
#[derive(Args, Debug, Clone, Default)]
pub struct LocalEngineArgs {
    /// SNMPv3 sender local engine-id as hex bytes
    #[arg(long)]
    pub local_engine_id: Option<String>,
    /// SNMPv3 sender local engineBoots
    #[arg(long)]
    pub local_engine_boots: Option<i64>,
    /// SNMPv3 sender local engineTime
    #[arg(long)]
    pub local_engine_time: Option<i64>,
}

/// The inform command's hidden local-engine options: parsed (so the reference's
/// "--local-engine-* options are only valid for SNMPv3 trap" rejection is
/// reachable) but suppressed from help (common.py `add_local_engine_options`
/// with `hidden=True`, cli/main.py:147).
#[derive(Args, Debug, Clone, Default)]
pub struct HiddenLocalEngineArgs {
    #[arg(long, hide = true)]
    pub local_engine_id: Option<String>,
    #[arg(long, hide = true)]
    pub local_engine_boots: Option<i64>,
    #[arg(long, hide = true)]
    pub local_engine_time: Option<i64>,
}

/// SNMPv1 Trap-PDU fields for the trap command (common.py
/// `add_v1_trap_options`).
#[derive(Args, Debug, Clone, Default)]
pub struct V1TrapArgs {
    /// SNMPv1 enterprise OID for the Trap-PDU (required with --snmp-version 1)
    #[arg(long)]
    pub enterprise: Option<String>,
    /// SNMPv1 agent-address field of the Trap-PDU (default: 0.0.0.0)
    #[arg(long)]
    pub agent_addr: Option<String>,
    /// SNMPv1 generic-trap code, 0-6 (default: 6, enterpriseSpecific)
    #[arg(long)]
    pub generic_trap: Option<u8>,
    /// SNMPv1 specific-trap code (default: 0)
    #[arg(long)]
    pub specific_trap: Option<i32>,
    /// SNMPv1 timestamp in centiseconds (default: 0)
    #[arg(long)]
    pub timestamp: Option<u32>,
}

/// Options common to the live manager commands (common.py `add_live_options`).
#[derive(Args, Debug, Clone)]
pub struct LiveArgs {
    /// Target agent hostname or IP address
    #[arg(long)]
    pub host: String,
    /// Target UDP port (default: 161)
    #[arg(long, default_value_t = 161)]
    pub port: u16,
    #[command(flatten)]
    pub security: SecurityArgs,
    /// SNMPv3 contextName as UTF-8 text (default: empty)
    #[arg(long, default_value = "")]
    pub context_name: String,
    /// Request timeout in seconds (default: 2.0)
    #[arg(long, default_value_t = 2.0)]
    pub timeout: f64,
    /// Retry count per request (default: 1)
    #[arg(long, default_value_t = 1)]
    pub retries: u32,
    /// Compiled module JSON file or bundle directory for symbolic translation
    #[arg(long)]
    pub bundle: Option<PathBuf>,
    /// Render numeric OIDs in text output even when a bundle is loaded
    #[arg(long)]
    pub numeric: bool,
    /// Emit machine-readable JSON output
    #[arg(long)]
    pub json: bool,
}

/// `get` / `getnext` positional targets.
#[derive(Args, Debug, Clone)]
pub struct TargetsArgs {
    #[command(flatten)]
    pub live: LiveArgs,
    /// Numeric OIDs or MODULE::symbol targets
    #[arg(required = true)]
    pub targets: Vec<String>,
}

/// `getbulk` positional targets plus the bulk knobs.
#[derive(Args, Debug, Clone)]
pub struct BulkArgs {
    #[command(flatten)]
    pub live: LiveArgs,
    /// Numeric OIDs or MODULE::symbol targets
    #[arg(required = true)]
    pub targets: Vec<String>,
    /// Number of non-repeaters (default: 0)
    #[arg(long, default_value_t = 0)]
    pub non_repeaters: u32,
    /// Maximum repetitions per repeating target (default: 10)
    #[arg(long, default_value_t = 10)]
    pub max_repetitions: u32,
}

/// `walk` options.
#[derive(Args, Debug, Clone)]
pub struct WalkArgs {
    #[command(flatten)]
    pub live: LiveArgs,
    /// Numeric OID or MODULE::symbol subtree root
    pub root: String,
    /// Maximum repetitions for bulk walk steps (default: 10)
    #[arg(long, default_value_t = 10)]
    pub max_repetitions: u32,
    /// Use GETNEXT rather than GETBULK during the walk
    #[arg(long)]
    pub no_bulk: bool,
}

/// `bulkwalk` options.
#[derive(Args, Debug, Clone)]
pub struct BulkWalkArgs {
    #[command(flatten)]
    pub live: LiveArgs,
    /// Numeric OID or MODULE::symbol subtree root
    pub root: String,
    /// Maximum repetitions per bulk request (default: 10)
    #[arg(long, default_value_t = 10)]
    pub max_repetitions: u32,
}

/// Options common to the outbound notification commands (common.py
/// `add_notifier_options` plus the notification positional and the
/// `_add_notification_send_arguments` flags).
#[derive(Args, Debug, Clone)]
pub struct NotifierArgs {
    /// Target notification receiver hostname or IP
    #[arg(long)]
    pub host: String,
    /// Target UDP port (default: 162)
    #[arg(long, default_value_t = 162)]
    pub port: u16,
    #[command(flatten)]
    pub security: SecurityArgs,
    /// SNMPv3 contextName as UTF-8 text (default: empty)
    #[arg(long, default_value = "")]
    pub context_name: String,
    /// Request timeout in seconds (default: 2.0)
    #[arg(long, default_value_t = 2.0)]
    pub timeout: f64,
    /// Retry count per request (default: 1)
    #[arg(long, default_value_t = 1)]
    pub retries: u32,
    /// Compiled module JSON file or bundle directory for symbolic translation
    #[arg(long)]
    pub bundle: Option<PathBuf>,
    /// Numeric OID or MODULE::symbol notification target (not used with
    /// --snmp-version 1)
    pub notification: Option<String>,
    /// sysUpTime.0 value in centiseconds (default: 0)
    #[arg(long, default_value_t = 0)]
    pub uptime: u32,
    /// Repeatable OID=TYPE:VALUE notification varbind
    #[arg(long = "varbind")]
    pub varbinds: Vec<String>,
    /// Emit machine-readable JSON output
    #[arg(long)]
    pub json: bool,
}

/// `trap` options: notifier options + v1 Trap-PDU fields + local engine.
#[derive(Args, Debug, Clone)]
pub struct TrapArgs {
    #[command(flatten)]
    pub notifier: NotifierArgs,
    #[command(flatten)]
    pub v1_trap: V1TrapArgs,
    #[command(flatten)]
    pub local_engine: LocalEngineArgs,
}

/// `inform` options: notifier options + `--numeric` + hidden local engine.
#[derive(Args, Debug, Clone)]
pub struct InformArgs {
    #[command(flatten)]
    pub notifier: NotifierArgs,
    /// Render numeric OIDs in text output even when a bundle is loaded
    #[arg(long)]
    pub numeric: bool,
    #[command(flatten)]
    pub local_engine: HiddenLocalEngineArgs,
}

/// `listen` options (common.py `add_listener_options`).
#[derive(Args, Debug, Clone)]
pub struct ListenArgs {
    /// Listener bind hostname or IP address (default: 0.0.0.0)
    #[arg(long, default_value = "0.0.0.0")]
    pub host: String,
    /// Listener UDP port (default: 162)
    #[arg(long, default_value_t = 162)]
    pub port: u16,
    /// SNMP version for inbound notifications (default: 2c); v1 and 2c share
    /// the community-based listener
    #[arg(
        long,
        default_value = "2c",
        value_parser = ["1", "2c", "3"]
    )]
    pub snmp_version: String,
    /// Allowed SNMPv1/v2c community string; repeat to allow multiple values
    #[arg(long = "community")]
    pub communities: Vec<String>,
    #[command(flatten)]
    pub usm: UsmArgs,
    #[command(flatten)]
    pub local_engine: LocalEngineArgs,
    /// Compiled module JSON file or bundle directory for symbolic translation
    #[arg(long)]
    pub bundle: Option<PathBuf>,
    /// Number of notifications to receive before exiting (default: 0, run
    /// until interrupted)
    #[arg(long, default_value_t = 0, allow_hyphen_values = true)]
    pub count: i64,
    /// Render numeric OIDs in text output even when a bundle is loaded
    #[arg(long)]
    pub numeric: bool,
    /// Emit one JSON object per received notification
    #[arg(long)]
    pub json: bool,
}

/// `decode-notification` options (common.py `add_decode_security_options` +
/// the input group from cli/main.py:167–192).
#[derive(Args, Debug, Clone)]
pub struct DecodeArgs {
    /// SNMP version of the encoded notification (default: 2c)
    #[arg(
        long,
        default_value = "2c",
        value_parser = ["1", "2c", "3"]
    )]
    pub snmp_version: String,
    #[command(flatten)]
    pub usm: UsmArgs,
    /// Compiled module JSON file or bundle directory for symbolic translation
    #[arg(long)]
    pub bundle: Option<PathBuf>,
    /// Hex-encoded SNMP message
    #[arg(
        long = "hex",
        conflicts_with = "file_input",
        required_unless_present = "file_input"
    )]
    pub hex_input: Option<String>,
    /// Path to raw BER-encoded SNMP message bytes
    #[arg(long = "file", conflicts_with = "hex_input")]
    pub file_input: Option<PathBuf>,
    /// Render numeric OIDs in text output even when a bundle is loaded
    #[arg(long)]
    pub numeric: bool,
    /// Emit machine-readable JSON output
    #[arg(long)]
    pub json: bool,
}

/// `translate` options.
#[derive(Args, Debug, Clone)]
pub struct TranslateArgs {
    /// Compiled module JSON file or bundle directory for symbolic translation
    #[arg(long, required = true)]
    pub bundle: PathBuf,
    /// Numeric OID or MODULE::symbol target
    pub target: String,
}
