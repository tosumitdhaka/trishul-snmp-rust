//! Codec-only microbench: trishul-snmp decode of the same golden v2c GET.

use std::hint::black_box;
use std::time::Instant;

use trishul_snmp::codec::message::decode_message;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn main() {
    let data = unhex("302702010104067075626c6963a01a0202044d020100020100300e300c06082b060102010103000500");
    assert!(decode_message(&data).is_ok(), "decode failed: {e:?}", e = decode_message(&data).unwrap_err());

    let n = 50_000;
    for _ in 0..1_000 {
        let _ = decode_message(black_box(&data));
    }

    let t0 = Instant::now();
    for _ in 0..n {
        let m = decode_message(black_box(&data)).unwrap();
        black_box(&m);
    }
    let dt = t0.elapsed().as_secs_f64();
    println!("rust-codec: {n} decodes in {dt:.3}s -> {:.3} us/decode", dt * 1e6 / n as f64);
}
