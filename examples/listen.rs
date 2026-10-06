//! Example: listen for one SNMPv2c trap and print the event fields.
//!
//! Usage: `cargo run --example listen [HOST] [PORT] [COMMUNITY]`
//! Defaults: `0.0.0.0:162`, community `public`. The example exits after the
//! first accepted event.
//!
//! Send a trap from a second terminal, e.g. with the repo's own CLI against
//! the printed port:
//!
//! ```sh
//! cargo run -- trap --host 127.0.0.1 --port <printed port> 1.3.6.1.6.3.1.1.5.3
//! ```

use trishul_snmp::notify::listener::{ListenerConfig, NotificationListener};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0".to_string());
    let port = std::env::args()
        .nth(2)
        .map(|s| s.parse().expect("PORT must be a number"))
        .unwrap_or(162);
    let community = std::env::args()
        .nth(3)
        .unwrap_or_else(|| "public".to_string());

    let listener = NotificationListener::bind(ListenerConfig {
        host,
        port,
        communities: Some(vec![community.into_bytes()]),
        ..Default::default()
    })
    .await?;
    println!("listening on {} for one v2c trap...", listener.local_addr());

    let event = listener.recv().await.expect("listener closed")?;
    println!(
        "notification: pdu_type={} request_id={}",
        event.pdu_type, event.request_id
    );
    if let Some(notification_oid) = &event.notification_oid {
        println!("  notification_oid = {}", notification_oid.display());
    }
    if let Some(uptime) = event.uptime {
        println!("  uptime = {uptime}");
    }
    for varbind in &event.varbinds {
        println!("  {} = {}", varbind.oid.display(), varbind.value);
    }
    Ok(())
}
