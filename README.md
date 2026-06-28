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
maxminddb = "0.29"
```

Enable optional features as needed:

```toml
[dependencies]
maxminddb = { version = "0.29", features = ["mmap"] }
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

## Iterating networks

Use `within()` to iterate over the networks contained in a CIDR range, or
`networks()` to iterate over the whole database. The example below uses the
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
- **`simdutf8`**: SIMD-accelerated UTF-8 validation
- **`unsafe-str-decode`**: Skip UTF-8 validation (requires trusted data)

Enable in `Cargo.toml`:

```toml
[dependencies]
maxminddb = { version = "0.29", features = ["mmap"] }
```

Note: `simdutf8` and `unsafe-str-decode` are mutually exclusive.

## Documentation

[API documentation on docs.rs](https://docs.rs/maxminddb)

## Benchmarks

The project includes benchmarks using [Criterion.rs](https://github.com/bheisler/criterion.rs).

First you need to have a working copy of the GeoIP City database.
You can fetch it from [here](https://dev.maxmind.com/geoip/geoip2/geolite2/).

Place it in the root folder as `GeoIP2-City.mmdb`.

Once this is done, run

```
cargo bench
```

Two focused benchmarks are especially useful while iterating on changes:

```bash
cargo bench --bench lookup
cargo bench --bench serde_usage
```

If [gnuplot](http://www.gnuplot.info/) is installed, Criterion.rs can generate
an HTML report displaying the results of the benchmark under
`target/criterion/report/index.html`.

## Contributing

Contributions welcome! Please fork the repository and open a pull request
with your changes.

## License

This is free software, licensed under the ISC license.
