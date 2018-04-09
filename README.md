# Rust MaxMind DB Reader #

[![Build Status](https://travis-ci.org/oschwald/maxminddb-rust.svg?branch=master)](https://travis-ci.org/oschwald/maxminddb-rust)

This library reads the MaxMind DB format, including the GeoIP2 and GeoLite2
databases.

## Building ##

To build everything:

```
cargo build
```

## Testing ##

This crate manages its test data within a git submodule.
To run the tests, you will first need to run the following command.

```bash
git submodule update --init
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

