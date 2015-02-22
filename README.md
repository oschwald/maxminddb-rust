# Rust MaxMind DB Reader #

[![Build Status](https://travis-ci.org/oschwald/maxminddb-rust.svg?branch=master)](https://travis-ci.org/oschwald/maxminddb-rust)

This library reads the MaxMind DB format, including the GeoIP2 and GeoLite2
databases.

## Rust Version Supported ##

This project tracks Rust master. Previous releases are not currently
supported.

## Building ##

To build everything:

```
make all check
```

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
maxminddb = "0.1.7"
```

and this to your crate root:

```rust
extern crate maxminddb;
```

## Example ##

See `example/lookup.rs` for a basic example.

## Contributing ##

Contributions welcome! Please fork the repository and open a pull request
with your changes.

## License ##

This is free software, licensed under the Apache License, Version 2.0.

