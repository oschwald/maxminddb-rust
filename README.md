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
maxminddb = "0.27"
```

## Example

```rust
use maxminddb::{geoip2, Reader};
use std::net::IpAddr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let reader = Reader::open_readfile("/path/to/GeoLite2-City.mmdb")?;

    let ip: IpAddr = "89.160.20.128".parse()?;
    let result = reader.lookup(ip)?;

    if let Some(city) = result.decode::<geoip2::City>()? {
        println!("Country: {}", city.country.iso_code.unwrap_or("N/A"));
        println!("City: {}", city.city.names.english.unwrap_or("N/A"));
    }

    Ok(())
}
```

See the [examples](examples/) directory for more usage patterns.

## Features

Optional features:

- **`mmap`**: Memory-mapped file access for long-running applications
- **`simdutf8`**: SIMD-accelerated UTF-8 validation
- **`unsafe-str-decode`**: Skip UTF-8 validation (requires trusted data)

Enable in `Cargo.toml`:

```toml
[dependencies]
maxminddb = { version = "0.27", features = ["mmap"] }
```

Note: `simdutf8` and `unsafe-str-decode` are mutually exclusive.

## Documentation

[API documentation on docs.rs](https://docs.rs/maxminddb)

## Benchmarks

The projects include benchmarks using [Criterion.rs](https://github.com/bheisler/criterion.rs).

First you need to have a working copy of the GeoIP City database.
You can fetch it from [here](https://dev.maxmind.com/geoip/geoip2/geolite2/).

Place it in the root folder as `GeoIP2-City.mmdb`.

Once this is done, run

```
cargo bench
```

If [gnuplot](http://www.gnuplot.info/) is installed, Criterion.rs can generate
an HTML report displaying the results of the benchmark under
`target/criterion/report/index.html`.

## Contributing

Contributions welcome! Please fork the repository and open a pull request
with your changes.

## License

This is free software, licensed under the ISC license.
