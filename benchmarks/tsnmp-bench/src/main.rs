use std::time::Instant;
use trishul_snmp::manager::walk::WalkOptions;
use trishul_snmp::manager::{Manager, V2cConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = V2cConfig {
        port: 1199,
        ..Default::default()
    };
    let m = Manager::connect_v2c(cfg).await?;

    // warmup
    m.get(["1.3.6.1.2.1.1.1.0"]).await?;

    let n = 200;
    let t0 = Instant::now();
    for _ in 0..n {
        m.get(["1.3.6.1.2.1.1.1.0"]).await?;
    }
    let dt = t0.elapsed().as_secs_f64();
    println!(
        "rust-lib: {n} sequential gets in {dt:.3}s -> {:.1} req/s ({:.0} us/req)",
        n as f64 / dt,
        dt * 1e6 / n as f64
    );

    m.walk("1.3.6.1.2.1", WalkOptions::default()).await?;
    let t0 = Instant::now();
    let vbs = m.walk("1.3.6.1.2.1", WalkOptions::default()).await?;
    let dt = t0.elapsed().as_secs_f64();
    println!("rust-lib: mib-2 walk: {} varbinds in {dt:.3}s", vbs.len());

    Ok(())
}
