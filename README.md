# Rust MaxMind DB Reader #

[![Build Status](https://travis-ci.org/oschwald/maxminddb-rust.svg?branch=master)](https://travis-ci.org/oschwald/maxminddb-rust) [![crates.io](	https://img.shields.io/crates/v/maxminddb.svg)](https://crates.io/crates/maxminddb) [![Released API docs](https://docs.rs/maxminddb/badge.svg)](http://docs.rs/maxminddb) [![Master API docs](https://img.shields.io/badge/docs-master-green.svg)](https://oschwald.github.io/maxminddb-rust/)

This library reads the MaxMind DB format, including the GeoIP2 and GeoLite2
databases.

## Building ##

To build everything:

```
cargo build
```

## Usage ##

Add this to your `Cargo.toml`:

```toml
[dependencies]
maxminddb = "0.8.1"
```

and this to your crate root:

```rust
extern crate maxminddb;
```

## API Documentation ##

The API docs are on [GitHub Pages](http://oschwald.github.io/maxminddb-rust/maxminddb/struct.Reader.html).

## Example ##

See [`examples/lookup.rs`](https://github.com/oschwald/maxminddb-rust/blob/master/examples/lookup.rs) for a basic example.

## Contributing ##

Contributions welcome! Please fork the repository and open a pull request
with your changes.

## License ##

This is free software, licensed under the ISC license.

