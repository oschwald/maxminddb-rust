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
maxminddb = "0.26"
```

and this to your crate root:

```rust
extern crate maxminddb;
```

## API Documentation

The API docs are on [Docs.rs](https://docs.rs/maxminddb/latest/maxminddb/struct.Reader.html).

## Example

See [`examples/lookup.rs`](https://github.com/oschwald/maxminddb-rust/blob/main/examples/lookup.rs) for a basic example.

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

Result of doing 100 random IP lookups:

![](/assets/pdf_small.svg)

## Contributing

Contributions welcome! Please fork the repository and open a pull request
with your changes.

## License

This is free software, licensed under the ISC license.
