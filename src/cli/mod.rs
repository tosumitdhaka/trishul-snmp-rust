//! CLI entry point (← cli/main.py)
//!
//! Thin command layer over the library: parse (clap), validate
//! (`common.rs`), run, render (`output.rs`). Exit codes follow the reference
//! exactly (docs/cli.md): 0 success, 1 runtime/translation/protocol failure
//! or non-zero SNMP error status, 2 invalid CLI usage (clap's own parse
//! errors).
//!
//! The reference's per-command manager/notifier construction
//! (`_manager_from_args` / `_notifier_from_args`) is a shared `connect_*`
//! path here, exactly as the anti-boilerplate rule requires.

mod args;
mod common;
mod output;

use std::future::Future;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;

use crate::cli::args::{
    BulkArgs, BulkWalkArgs, Cli, Command, DecodeArgs, InformArgs, ListenArgs, LiveArgs,
    LocalEngineArgs, TargetsArgs, TranslateArgs, TrapArgs, WalkArgs,
};
use crate::cli::common::{
    CliSecurity, ListenerCliSecurity, parse_cli_security, parse_decode_notification_user,
    parse_listener_cli_security, parse_notification_varbinds, validate_inform_version,
    validate_trap_version_flags,
};
use crate::cli::output::{
    render_notification_event, render_request_id, render_response, render_translation,
    render_v1_trap_timestamp, render_walk,
};
use crate::error::Error;
use crate::manager::Manager;
use crate::manager::walk::WalkOptions;
use crate::mib::MibBundle;
use crate::mib::loader::load_bundle;
use crate::notify::event::decode_notification;
use crate::notify::listener::{ListenerConfig, NotificationListener, V3NotificationListener};
use crate::notify::sender::{Notifier, V1TrapSpec};
use crate::security::usm::V3Config;
use crate::time::{SystemClock, SystemRng};
use crate::types::varbind::ErrorStatus;

/// Runs the CLI and returns the process exit code.
pub fn run() -> i32 {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Version => handle_version(),
        Command::Translate(args) => handle_translate(args),
        Command::Get(args) => block_on(handle_get(args)),
        Command::GetNext(args) => block_on(handle_get_next(args)),
        Command::GetBulk(args) => block_on(handle_get_bulk(args)),
        Command::Walk(args) => block_on(handle_walk(args)),
        Command::BulkWalk(args) => block_on(handle_bulk_walk(args)),
        Command::Trap(args) => block_on(handle_trap(args)),
        Command::Inform(args) => block_on(handle_inform(args)),
        Command::Listen(args) => block_on(handle_listen(args)),
        Command::DecodeNotification(args) => handle_decode_notification(args),
    };
    match result {
        Ok(code) => code,
        Err(message) => {
            eprintln!("tsnmp: {message}");
            1
        }
    }
}

// ── handlers ────────────────────────────────────────────────────────────────

fn handle_version() -> Result<i32, String> {
    println!("{}", crate::VERSION);
    Ok(0)
}

fn handle_translate(args: TranslateArgs) -> Result<i32, String> {
    // `--bundle` is clap-required, so the reference's unreachable
    // "translate requires --bundle" guard needs no Rust equivalent.
    let bundle = load_bundle(&args.bundle).map_err(cli_error)?;
    println!(
        "{}",
        render_translation(&bundle.translate(&args.target).map_err(cli_error)?)
    );
    Ok(0)
}

async fn handle_get(args: TargetsArgs) -> Result<i32, String> {
    run_response_command(&args.live, &args.targets, |manager, targets| {
        Box::pin(async move { manager.get(targets).await })
    })
    .await
}

async fn handle_get_next(args: TargetsArgs) -> Result<i32, String> {
    run_response_command(&args.live, &args.targets, |manager, targets| {
        Box::pin(async move { manager.get_next(targets).await })
    })
    .await
}

async fn handle_get_bulk(args: BulkArgs) -> Result<i32, String> {
    let non_repeaters = args.non_repeaters;
    let max_repetitions = args.max_repetitions;
    run_response_command(&args.live, &args.targets, |manager, targets| {
        Box::pin(async move {
            manager
                .get_bulk(targets, non_repeaters, max_repetitions)
                .await
        })
    })
    .await
}

async fn handle_walk(args: WalkArgs) -> Result<i32, String> {
    let bundle = load_optional_bundle(args.live.bundle.as_ref())?;
    let security = parse_cli_security(
        &args.live.security,
        &args.live.context_name,
        false,
        false,
        &LocalEngineArgs::default(),
    )?;
    let manager = connect_manager(
        &security,
        &args.live.host,
        args.live.port,
        args.live.timeout,
        args.live.retries,
        bundle,
    )
    .await?;
    let opts = WalkOptions {
        bulk: !args.no_bulk,
        max_repetitions: args.max_repetitions,
    };
    let varbinds = manager
        .walk(args.root.as_str(), opts)
        .await
        .map_err(cli_error)?;
    println!(
        "{}",
        render_walk(&varbinds, args.live.json, args.live.numeric)
    );
    Ok(0)
}

async fn handle_bulk_walk(args: BulkWalkArgs) -> Result<i32, String> {
    let bundle = load_optional_bundle(args.live.bundle.as_ref())?;
    let security = parse_cli_security(
        &args.live.security,
        &args.live.context_name,
        false,
        false,
        &LocalEngineArgs::default(),
    )?;
    let manager = connect_manager(
        &security,
        &args.live.host,
        args.live.port,
        args.live.timeout,
        args.live.retries,
        bundle,
    )
    .await?;
    let opts = WalkOptions {
        bulk: true,
        max_repetitions: args.max_repetitions,
    };
    let varbinds = manager
        .bulkwalk(args.root.as_str(), opts)
        .await
        .map_err(cli_error)?;
    println!(
        "{}",
        render_walk(&varbinds, args.live.json, args.live.numeric)
    );
    Ok(0)
}

async fn handle_trap(args: TrapArgs) -> Result<i32, String> {
    validate_trap_version_flags(
        &args.notifier.security.snmp_version,
        &args.notifier.notification,
        args.notifier.uptime,
        &args.v1_trap,
    )?;
    let bundle = load_optional_bundle(args.notifier.bundle.as_ref())?;
    let varbinds = parse_notification_varbinds(&args.notifier.varbinds, bundle.as_deref())?;
    let security = parse_cli_security(
        &args.notifier.security,
        &args.notifier.context_name,
        true,
        true,
        &args.local_engine,
    )?;

    if args.notifier.security.snmp_version == "1" {
        let notifier = connect_notifier(
            &security,
            &args.notifier.host,
            args.notifier.port,
            args.notifier.timeout,
            args.notifier.retries,
            bundle,
        )
        .await?;
        let enterprise = args
            .v1_trap
            .enterprise
            .clone()
            .expect("validated: --enterprise is required with --snmp-version 1");
        let agent_addr = args
            .v1_trap
            .agent_addr
            .as_deref()
            .unwrap_or("0.0.0.0")
            .parse::<Ipv4Addr>()
            .map_err(|_| {
                format!(
                    "Invalid agent address: {}",
                    args.v1_trap.agent_addr.as_deref().unwrap_or("0.0.0.0")
                )
            })?;
        let spec = V1TrapSpec {
            enterprise: crate::target::Target::from(enterprise.as_str()),
            agent_addr,
            generic_trap: args.v1_trap.generic_trap.unwrap_or(6),
            specific_trap: args.v1_trap.specific_trap.unwrap_or(0),
            timestamp: args.v1_trap.timestamp.unwrap_or(0),
            varbinds,
        };
        let timestamp = notifier.send_v1_trap(spec).await.map_err(cli_error)?;
        println!(
            "{}",
            render_v1_trap_timestamp(timestamp, args.notifier.json)
        );
        return Ok(0);
    }

    let Some(notification) = &args.notifier.notification else {
        return Err("trap requires a notification OID target".to_string());
    };
    let notifier = connect_notifier(
        &security,
        &args.notifier.host,
        args.notifier.port,
        args.notifier.timeout,
        args.notifier.retries,
        bundle,
    )
    .await?;
    let request_id = notifier
        .send_trap(notification.as_str(), &varbinds, args.notifier.uptime)
        .await
        .map_err(cli_error)?;
    println!("{}", render_request_id(request_id, args.notifier.json));
    Ok(0)
}

async fn handle_inform(args: InformArgs) -> Result<i32, String> {
    validate_inform_version(&args.notifier.security.snmp_version)?;
    let Some(notification) = &args.notifier.notification else {
        return Err("inform requires a notification OID target".to_string());
    };
    let bundle = load_optional_bundle(args.notifier.bundle.as_ref())?;
    let varbinds = parse_notification_varbinds(&args.notifier.varbinds, bundle.as_deref())?;
    let security = parse_cli_security(
        &args.notifier.security,
        &args.notifier.context_name,
        false,
        false,
        &args.local_engine,
    )?;
    let notifier = connect_notifier(
        &security,
        &args.notifier.host,
        args.notifier.port,
        args.notifier.timeout,
        args.notifier.retries,
        bundle,
    )
    .await?;
    let response = notifier
        .send_inform(notification.as_str(), &varbinds, args.notifier.uptime)
        .await
        .map_err(cli_error)?;
    println!(
        "{}",
        render_response(&response, args.notifier.json, args.numeric)
    );
    Ok(if response.error_status == ErrorStatus::NoError {
        0
    } else {
        1
    })
}

async fn handle_listen(args: ListenArgs) -> Result<i32, String> {
    if args.count < 0 {
        return Err("--count cannot be negative".to_string());
    }
    let bundle = load_optional_bundle(args.bundle.as_ref())?;
    let security = parse_listener_cli_security(
        &args.snmp_version,
        &args.communities,
        &args.usm,
        &args.local_engine,
    )?;
    let remaining = args.count as usize;
    let mut received = 0usize;

    let base_config = ListenerConfig {
        host: args.host.clone(),
        port: args.port,
        bundle,
        ..Default::default()
    };
    match security {
        ListenerCliSecurity::Community { communities } => {
            let listener = NotificationListener::bind(ListenerConfig {
                communities: communities
                    .map(|list| list.into_iter().map(|c| c.into_bytes()).collect()),
                ..base_config
            })
            .await
            .map_err(cli_error)?;
            while remaining == 0 || received < remaining {
                let Some(event) = listener.recv().await else {
                    break;
                };
                let event = event.map_err(cli_error)?;
                if received > 0 && !args.json {
                    println!();
                }
                println!(
                    "{}",
                    render_notification_event(&event, args.json, args.numeric, args.json)
                );
                received += 1;
            }
        }
        ListenerCliSecurity::V3 { user, local_engine } => {
            let listener = V3NotificationListener::bind(base_config, user, local_engine)
                .await
                .map_err(cli_error)?;
            while remaining == 0 || received < remaining {
                let Some(event) = listener.recv().await else {
                    break;
                };
                let event = event.map_err(cli_error)?;
                if received > 0 && !args.json {
                    println!();
                }
                println!(
                    "{}",
                    render_notification_event(&event, args.json, args.numeric, args.json)
                );
                received += 1;
            }
        }
    }
    Ok(0)
}

fn handle_decode_notification(args: DecodeArgs) -> Result<i32, String> {
    let bundle = load_optional_bundle(args.bundle.as_ref())?;
    let user = parse_decode_notification_user(&args.snmp_version, &args.usm)?;
    let data = load_notification_bytes(&args)?;
    let event =
        decode_notification(&data, None, user.as_ref(), bundle.as_deref()).map_err(cli_error)?;
    println!(
        "{}",
        render_notification_event(&event, args.json, args.numeric, false)
    );
    Ok(0)
}

// ── shared plumbing (the reference's `_manager_from_args` /
// ── `_notifier_from_args` / `_run_response_command`) ────────────────────────

/// The shared single-exchange command path (main.py:_run_response_command):
/// connect, run one operation, render, exit 0 on no_error else 1. The
/// operation is a closure returning a pinned future borrowing the manager
/// (HRTB) so `get`/`get_next`/`get_bulk` share one implementation without
/// boxing the caller-side async blocks.
async fn run_response_command<F>(
    live: &LiveArgs,
    targets: &[String],
    operation: F,
) -> Result<i32, String>
where
    F: for<'a> FnOnce(&'a Manager, Vec<crate::target::Target>) -> BoxResponse<'a>,
{
    let bundle = load_optional_bundle(live.bundle.as_ref())?;
    let security = parse_cli_security(
        &live.security,
        &live.context_name,
        false,
        false,
        &LocalEngineArgs::default(),
    )?;
    let manager = connect_manager(
        &security,
        &live.host,
        live.port,
        live.timeout,
        live.retries,
        bundle,
    )
    .await?;
    let target_refs: Vec<crate::target::Target> = targets
        .iter()
        .map(|target| crate::target::Target::from(target.as_str()))
        .collect();
    let response = operation(&manager, target_refs).await.map_err(cli_error)?;
    println!("{}", render_response(&response, live.json, live.numeric));
    Ok(if response.error_status == ErrorStatus::NoError {
        0
    } else {
        1
    })
}

/// A pinned response future borrowing the manager (used by
/// [`run_response_command`]).
type BoxResponse<'a> = std::pin::Pin<
    Box<dyn Future<Output = Result<crate::types::varbind::Response, Error>> + Send + 'a>,
>;

/// Loads the optional bundle (main.py:load_bundle_from_args).
fn load_optional_bundle(path: Option<&PathBuf>) -> Result<Option<Arc<MibBundle>>, String> {
    match path {
        Some(path) => load_bundle(path).map(Arc::new).map(Some).map_err(cli_error),
        None => Ok(None),
    }
}

/// The shared manager connect path (main.py:_manager_from_args).
async fn connect_manager(
    security: &CliSecurity,
    host: &str,
    port: u16,
    timeout: f64,
    retries: u32,
    bundle: Option<Arc<MibBundle>>,
) -> Result<Manager, String> {
    let timeout = Duration::from_secs_f64(timeout);
    match security {
        CliSecurity::Community { community, version } => {
            let config = crate::security::community::CommunityConfig {
                host: host.to_string(),
                port,
                community: community.clone(),
                bundle,
                timeout,
                retries,
                rng: Arc::new(SystemRng),
            };
            if version == "1" {
                Manager::connect_v1(config).await.map_err(cli_error)
            } else {
                Manager::connect_v2c(config).await.map_err(cli_error)
            }
        }
        CliSecurity::V3 {
            user,
            context_name,
            local_engine,
        } => Manager::connect_v3(V3Config {
            host: host.to_string(),
            port,
            user: user.clone(),
            context_name: context_name.clone(),
            local_engine: local_engine.clone(),
            bundle,
            timeout,
            retries,
            clock: Arc::new(SystemClock),
            rng: Arc::new(SystemRng),
        })
        .await
        .map_err(cli_error),
    }
}

/// The shared notifier connect path (main.py:_notifier_from_args).
async fn connect_notifier(
    security: &CliSecurity,
    host: &str,
    port: u16,
    timeout: f64,
    retries: u32,
    bundle: Option<Arc<MibBundle>>,
) -> Result<Notifier, String> {
    let timeout = Duration::from_secs_f64(timeout);
    match security {
        CliSecurity::Community { community, version } => {
            let config = crate::security::community::CommunityConfig {
                host: host.to_string(),
                port,
                community: community.clone(),
                bundle,
                timeout,
                retries,
                rng: Arc::new(SystemRng),
            };
            if version == "1" {
                Notifier::connect_v1(config).await.map_err(cli_error)
            } else {
                Notifier::connect_v2c(config).await.map_err(cli_error)
            }
        }
        CliSecurity::V3 {
            user,
            context_name,
            local_engine,
        } => Notifier::connect_v3(V3Config {
            host: host.to_string(),
            port,
            user: user.clone(),
            context_name: context_name.clone(),
            local_engine: local_engine.clone(),
            bundle,
            timeout,
            retries,
            clock: Arc::new(SystemClock),
            rng: Arc::new(SystemRng),
        })
        .await
        .map_err(cli_error),
    }
}

/// Maps library errors to the user-facing message. `WalkAborted` is rewrapped
/// into the reference's exact `WalkError` text ("walk aborted: agent reported
/// gen_err (error-index 1)") — the library's `Error::WalkAborted` Display is
/// the typed taxonomy's phrasing; the CLI restores reference parity at the
/// boundary (documented in docs/architecture.md §8).
fn cli_error(error: Error) -> String {
    match error {
        Error::WalkAborted { status, index } => {
            format!(
                "walk aborted: agent reported {} (error-index {index})",
                status.label()
            )
        }
        other => other.to_string(),
    }
}

/// Loads the decode-input bytes (main.py:_load_notification_bytes).
fn load_notification_bytes(args: &DecodeArgs) -> Result<Vec<u8>, String> {
    if let Some(hex_input) = &args.hex_input {
        return common::parse_hex_bytes(hex_input);
    }
    if let Some(file_input) = &args.file_input {
        return std::fs::read(file_input)
            .map_err(|error| format!("cannot read {}: {error}", file_input.display()));
    }
    Err("decode-notification requires --hex or --file".to_string())
}

/// Runs an async handler on a fresh current-thread runtime (asyncio.run).
fn block_on<F>(future: F) -> Result<i32, String>
where
    F: Future<Output = Result<i32, String>>,
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    runtime.block_on(future)
}
