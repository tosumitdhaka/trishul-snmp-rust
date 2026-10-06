# tsnmp

Alias crate: `tsnmp` and `trishul-snmp` are the same project.

This crate exists so both names on crates.io resolve to the Rust SNMP
toolkit — async SNMP manager (v1/v2c/v3-USM), notification send/receive
with replay guard, read-only responder, compiled-JSON MIB enrichment, and
the `tsnmp` CLI (11 subcommands).

Either name installs the same library and the same `tsnmp` binary:

```sh
cargo add trishul-snmp   # canonical
cargo add tsnmp          # alias, identical
```

Source, documentation, and releases:
<https://github.com/tosumitdhaka/trishul-snmp-rust>
