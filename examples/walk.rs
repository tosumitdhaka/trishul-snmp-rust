//! Example: walk a subtree and print the varbind count (v2c).
//!
//! Usage: `cargo run --example walk [HOST] [PORT] [COMMUNITY] [ROOT]`
//! Defaults: `127.0.0.1:161`, community `public`, root `1.3.6.1.2.1.1`
//! (the system subtree). The first few varbinds are printed alongside the
//! count so the walk result is inspectable.
//!
//! A good target is the repo's bench snmpd agent (see benchmarks/):
//!
//! ```sh
//! snmpd -C -f -c benchmarks/bench-snmpd.conf        # listens on 127.0.0.1:1199
//! cargo run --example walk 127.0.0.1 1199 public 1.3.6.1.2.1.1
//! ```

use std::time::Duration;

use trishul_snmp::{Manager, Target, V2cConfig, WalkOptions};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let port = std::env::args()
        .nth(2)
        .map(|s| s.parse().expect("PORT must be a number"))
        .unwrap_or(161);
    let community = std::env::args()
        .nth(3)
        .unwrap_or_else(|| "public".to_string());
    let root: Target = std::env::args()
        .nth(4)
        .unwrap_or_else(|| "1.3.6.1.2.1.1".to_string())
        .parse()?;

    let manager = Manager::connect_v2c(V2cConfig {
        host,
        port,
        community,
        timeout: Duration::from_secs(2),
        retries: 1,
        ..Default::default()
    })
    .await?;

    let varbinds = manager.walk(root, WalkOptions::default()).await?;
    println!("walked {} varbinds under the subtree", varbinds.len());
    for varbind in varbinds.iter().take(5) {
        println!("  {} = {}", varbind.oid.display(), varbind.value);
    }
    if varbinds.len() > 5 {
        println!("  ...");
    }
    Ok(())
}
