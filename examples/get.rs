//! Example: one SNMP GET against an agent (v2c).
//!
//! Usage: `cargo run --example get [HOST] [PORT] [COMMUNITY] [OID]`
//! Defaults: `127.0.0.1:161`, community `public`, OID `1.3.6.1.2.1.1.3.0`
//! (sysUpTime.0).
//!
//! A good target is the repo's bench snmpd agent (see benchmarks/):
//!
//! ```sh
//! snmpd -C -f -c benchmarks/bench-snmpd.conf        # listens on 127.0.0.1:1199
//! cargo run --example get 127.0.0.1 1199 public 1.3.6.1.2.1.1.1.0
//! ```

use std::time::Duration;

use trishul_snmp::{Manager, Target, V2cConfig};

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
    let oid: Target = std::env::args()
        .nth(4)
        .unwrap_or_else(|| "1.3.6.1.2.1.1.3.0".to_string())
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

    let response = manager.get([oid]).await?;
    for varbind in &response.varbinds {
        println!("{} = {}", varbind.oid.display(), varbind.value);
    }
    Ok(())
}
