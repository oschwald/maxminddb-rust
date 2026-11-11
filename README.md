# Rust MaxMind DB Reader

[![crates.io](https://img.shields.io/crates/v/maxminddb.svg)](https://crates.io/crates/maxminddb) [![Released API docs](https://docs.rs/maxminddb/badge.svg)](http://docs.rs/maxminddb)

This library reads the MaxMind DB format, including the GeoIP2 and GeoLite2
databases.

## Building

To build everything:

```
cargo build
```

## Testing

This crate manages its test data within a git submodule.
To run the tests, you will first need to run the following command.

```bash
git submodule update --init
```

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
maxminddb = "0.32"
```

## Example

```rust
use maxminddb::{geoip2, path, Reader};
use std::net::IpAddr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let reader = Reader::open_readfile("/path/to/GeoLite2-City.mmdb")?;

    let ip: IpAddr = "89.160.20.128".parse()?;
    let result = reader.lookup(ip)?;
    println!("Network: {}", result.network()?);

    if let Some(city) = result.decode::<geoip2::City>()? {
        println!("Country: {}", city.country.iso_code.unwrap_or("N/A"));
        println!("City: {}", city.city.names.english.unwrap_or("N/A"));
    }

    let iso_code: Option<&str> = result.decode_path(&path!["country", "iso_code"])?;
    println!("Country code via decode_path: {}", iso_code.unwrap_or("N/A"));

    Ok(())
}
```

`lookup()` returns a lightweight `LookupResult` handle. You can:

- Check whether a record exists with `has_data()`
- Read the matched network with `network()`
- Decode the full record with `decode()`
- Decode one field with `decode_path()`
- Reuse `offset()` as a cache key when many IPs share the same record

Every reader automatically builds a small prefix index. It skips up to eight
IPv4 tree steps or four IPv6 steps, using 1,360 bytes of table storage.
Building it adds a small one-time cost to opening a reader. It works with
owned, borrowed, and memory-mapped database buffers.

## Iterating networks

Use `within()` to iterate over database networks matching a CIDR range in the
database's search-tree address space, or `networks()` to iterate over the whole
database. Results are not clipped to the requested range and can include an
enclosing database network. Returned networks can use a different address family
than the requested CIDR. See the `Reader::within()` API documentation for IPv4/IPv6
representation rules.

The example below uses the
[`ipnetwork`](https://crates.io/crates/ipnetwork) crate, which is not
re-exported by `maxminddb`; add it to your own `Cargo.toml` to run this code.

```rust
use ipnetwork::IpNetwork;
use maxminddb::{Reader, WithinOptions};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let reader = Reader::open_readfile("/path/to/GeoLite2-City.mmdb")?;
    let cidr: IpNetwork = "89.160.20.0/24".parse()?;
    let opts = WithinOptions::default().skip_empty_values();

    for result in reader.within(cidr, opts)? {
        let lookup = result?;
        println!("{}", lookup.network()?);
    }

    Ok(())
}
```

See the [examples](examples/) directory for runnable programs, including:

- `cargo run --example lookup -- <database.mmdb> <ip>`
- `cargo run --example within -- <database.mmdb> <cidr>`

## Features

Optional features:

- **`mmap`**: Memory-mapped file access for long-running applications
- **`unsafe-str-decode`**: Skip UTF-8 validation when deserializing trusted
  database strings into Rust `str` or `String` values. Cross-runtime format
  adapters should prefer `deserialize_any_with_raw_strings()` and validate
  while constructing the target runtime's string type.

Enable in `Cargo.toml`:

```toml
[dependencies]
maxminddb = { version = "0.32", features = ["mmap"] }
```

## Documentation

[API documentation on docs.rs](https://docs.rs/maxminddb)

## Benchmarks

The project includes benchmarks using [Criterion.rs](https://github.com/bheisler/criterion.rs).

First you need to have a working copy of the GeoIP City database.
You can fetch it from [here](https://dev.maxmind.com/geoip/geoip2/geolite2/).

Place it in the root folder as `GeoLite2-City.mmdb`.

Once this is done, run

```
cargo bench
```

Two focused benchmarks are especially useful while iterating on changes:

```bash
cargo bench --bench lookup
cargo bench --bench serde_usage
```

The `serde_usage` suite covers typed records, ignored fields, generic JSON
values, raw-string adapters, and selective paths. The `decode_raw_strings`
case walks every record using borrowed identifier bytes and
`deserialize_any_with_raw_strings`, as language bindings do, without adding
another runtime's allocation costs. It detects decoder overhead that typed
record benchmarks can miss.

Criterion.rs generates an HTML report at `target/criterion/report/index.html`.
It uses gnuplot when available and the bundled Plotters backend otherwise.

The separate `lookup_workloads` benchmark emits JSON with five timing samples
and their median. It measures tree traversal, full City decoding, and reader
construction on deterministic random IPs and a reservoir sample of successful
networks across the database. Random workloads report their hit counts; hit
samples weight networks equally rather than weighting by network size. Both
City and Country databases can be used; decoding always requests `geoip2::City`.

```bash
cargo bench --bench lookup_workloads -- /path/to/GeoLite2-City.mmdb
```

Use the same database, compiler, build flags, and CPU affinity for comparisons.
`MMDB_BENCH_MS` sets each sample's minimum duration (default: 200 ms), and
`MMDB_BENCH_FILTER` selects measurement names by substring, such as `tree/` or
`open_buffer`. `open_buffer` includes automatic index construction, but
excludes disk reads. The lookup measurements run after opening and warmup.

## Contributing

Contributions welcome! Please fork the repository and open a pull request
with your changes.

## License

This is free software, licensed under the ISC license.
