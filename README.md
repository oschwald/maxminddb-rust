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
IPv4 tree steps or four IPv6 steps, using at most 1,360 bytes of table storage.
It works with owned, borrowed, and memory-mapped database buffers.

When many IPs share complete records, a typed cache can also avoid decoding:

```rust
let mut cache = reader.record_cache::<geoip2::City>();
let result = cache.lookup(ip)?;
if let Some(city) = result.data() {
    println!("Country: {}", city.country.iso_code.unwrap_or("N/A"));
}
```

This cache holds two decoded records and favors frequently reused values while
aging out old ones. Results expose records by reference without requiring
`Clone`. Drop a result before the next cache lookup; its network information
always describes the current IP. Concurrent consumers can each keep a cache
while sharing one reader.

Record caching is explicit because `decode<T>()` supports arbitrary types and
returns owned values. Cache memory depends on `T` and its allocations, and
workloads with little record reuse can be slower. The measured 3.9 KiB for a City
workload includes the prefix tables and record cache; it is not a fixed memory
limit. Ordinary lookups and selective decoding remain available.

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

`record_cache` compares the public typed cache with ordinary full decoding.
Both paths consume complete records by reference, and the benchmark checks
cached values, offsets, and networks against uncached results before timing.
It reports five timing samples, uncached measurements before and after the
cached measurement, reader construction, and cache initialization/destruction.

```bash
MMDB_CACHE_SCHEMA=city cargo bench --bench record_cache -- /path/to/GeoIP2-City.mmdb
MMDB_TRACK_ALLOC=1 cargo bench --bench record_cache -- /path/to/GeoIP2-City.mmdb
```

`MMDB_CACHE_SCHEMA` accepts `city`, `country`, `isp`, `anonymous`, and `value`
(full JSON). `MMDB_CACHE_WORKLOAD` optionally selects `mixed_random` or
`mixed_hits`; the default runs both. The random workload shuffles 65,536 uniform
IPs per family, so most IPv6 queries miss. The hit workload samples up to 8,192
successful networks per family, weighting networks equally. These are
sensitivity checks rather than models of production traffic. `MMDB_CACHE_SEED`
changes the deterministic seed, `MMDB_CACHE_COUNT` changes the random count per
family, and `MMDB_BENCH_MS` sets each sample's minimum duration (default: 100 ms).

Allocation tracking is enabled at compile time with `MMDB_TRACK_ALLOC=1` and
disables timing output. Its retained and peak bytes include the record cache's
inline storage and requested heap allocations, including values decoded on
misses. Add up to 1,360 bytes for the reader's prefix tables. The measurements
exclude the database buffer, reader metadata, allocator overhead, and stack
temporaries. Observed peaks depend on the database and workload.

## Contributing

Contributions welcome! Please fork the repository and open a pull request
with your changes.

## License

This is free software, licensed under the ISC license.
