# Change Log

## 0.27.0 - UNRELEASED

- **BREAKING CHANGE:** The `lookup` method now returns a `LookupResult` instead
  of `Option<T>`. The new API enables lazy decoding - data is only deserialized
  when explicitly requested via `decode()`. Migration:
  - Old: `reader.lookup::<City>(ip)?` returns `Option<City>`
  - New: `reader.lookup(ip)?.decode::<City>()` returns `City`
  - Check if data exists: `reader.lookup(ip)?.has_data()` returns `bool`
- **BREAKING CHANGE:** The `lookup_prefix` method has been removed. Use
  `reader.lookup(ip)?.network()` to get the network containing the IP.
- **BREAKING CHANGE:** The `Within` iterator now yields `LookupResult` instead
  of `WithinItem<T>`. Access the network via `result.network()?` and decode
  data via `result.decode::<T>()?`.
- **BREAKING CHANGE:** The `within()` method now takes a second `options`
  parameter of type `WithinOptions`. Use `Default::default()` for the previous
  behavior:
  - Old: `reader.within(cidr)?`
  - New: `reader.within(cidr, Default::default())?`
- Added `WithinOptions` struct to control network iteration behavior:
  - `include_aliased_networks()` - Include IPv4 networks multiple times when
    accessed via IPv6 aliases (e.g., `::ffff:0:0/96`, `2001::/32`, `2002::/16`)
  - `include_networks_without_data()` - Include networks that have no associated
    data record. `LookupResult::has_data()` returns `false` for these.
  - `skip_empty_values()` - Skip networks whose data is an empty map `{}` or
    empty array `[]`
- Added `networks()` method as a convenience for iterating over all networks in
  the database. Equivalent to `within("::/0", options)` for IPv6 databases or
  `within("0.0.0.0/0", options)` for IPv4-only databases.
- Added `LookupResult` type with methods:
  - `has_data()` - Check if data exists for this IP
  - `network()` - Get the network containing the IP
  - `offset()` - Get data offset for caching/deduplication
  - `decode()` - Deserialize full record (returns `Result<Option<T>>`)
  - `decode_path()` - Selectively decode specific fields by path
- Added `PathElement` enum for navigating nested structures:
  - `PathElement::Key("name")` - Navigate into map by key
  - `PathElement::Index(0)` - Navigate into array by index (0 = first element)
  - `PathElement::IndexFromEnd(0)` - Navigate from the end (0 = last element)
- Added `path!` macro for ergonomic path construction:
  - String literals become `Key` elements: `path!["country", "iso_code"]`
  - Non-negative integers become `Index` elements: `path!["array", 0]`
  - Negative integers become `IndexFromEnd` elements: `path!["array", -1]` (last element)
- `Metadata` and `WithinOptions` now implement `PartialEq` and `Eq` traits.
- Added `verify()` method for comprehensive database validation. Validates
  metadata, search tree structure, data section separator, and data records.
  Useful for validating database files after download or generation.
- Serde deserializer improvements:
  - Added size hints to `SeqAccess` and `MapAccess` for efficient collection
    pre-allocation
  - `is_human_readable()` now returns `false` since MMDB is a binary format
  - Implemented `deserialize_ignored_any` for efficient value skipping
  - Implemented `deserialize_enum` for string-to-enum deserialization
- Added recursion depth limit (512) matching libmaxminddb and the Go reader.
  This prevents stack overflow when decoding malformed databases with deeply
  nested structures.
- **BREAKING CHANGE:** The `InvalidDatabase` and `Decoding` error variants now
  use structured fields instead of a single string:
  - `InvalidDatabase { message, offset }` - includes optional byte offset
  - `Decoding { message, offset, path }` - includes optional byte offset and
    JSON-pointer-style path for locating the error
  - Pattern matching code must be updated (e.g., `InvalidDatabase(msg)` becomes
    `InvalidDatabase { message, .. }`)
- **BREAKING CHANGE:** A new `InvalidInput { message }` error variant has been
  added for user input errors (e.g., looking up an IPv6 address in an IPv4-only
  database). Previously this returned `InvalidDatabase`, which incorrectly
  suggested the database was corrupted.
- Error messages now include byte offsets when available, making it easier to
  debug malformed databases. The `#[non_exhaustive]` attribute is added to
  `MaxMindDbError` to allow future additions without breaking changes.

## 0.26.0 - 2025-03-28

- **BREAKING CHANGE:** The `lookup` and `lookup_prefix` methods now return
  `Ok(None)` or `Ok((None, prefix_len))` respectively when an IP address is
  valid but not found in the database (or has no associated data record),
  instead of returning an `Err(MaxMindDbError::AddressNotFoundError)`. Code
  previously matching on `AddressNotFoundError` must be updated to handle the
  `Ok(None)` / `Ok((None, prefix_len))` variants.
- **BREAKING CHANGE:** The `MaxMindDBError` enum has been renamed
  `MaxMindDbError` and variants have been renamed and refactored. For example,
  `IoError` is now `Io`, `InvalidDatabaseError` is now `InvalidDatabase`,
  `DecodingError` is now `Decoding`, `InvalidNetworkError` is now
  `InvalidNetwork`. The `MapError` variant has been replaced by `Mmap` (under
  the `mmap` feature flag). Code explicitly matching on the old variant names
  must be updated.
- **BREAKING CHANGE:** `MaxMindDbError` no longer implements `PartialEq`. This
  is because underlying error types like `std::io::Error` (now wrapped by the
  `Io` and `Mmap` variants) do not implement `PartialEq`. Code comparing errors
  directly using `==` or `assert_eq!` must be updated, typically by using
  `matches!` or by matching on the error kind and potentially its contents.
- Refactored `MaxMindDbError` handling using the `thiserror` crate. Variants
  like `Io`, `Mmap`, and `InvalidNetwork` now directly wrap the underlying
  error types (`std::io::Error`, `ipnetwork::IpNetworkError`).
- Errors wrapping underlying types (`Io`, `Mmap`, `InvalidNetwork`) now
  correctly implement `std::error::Error::source()`, allowing inspection of the
  original cause.
- The `Display` implementation for `MaxMindDbError` has been refined to
  generally show only the specific error details, often including the message
  from the source error, rather than prefixing with the variant name.
- `lookup_prefix` now returns the prefix length of the entry even when the
  value is not found.
- Fixed an internal bounds checking error when resolving data pointers. The
  previous logic could cause a panic on a corrupt database.

## 0.25.0 - 2025-02-16

- Serde will now skip serialization of the GeoIP2 struct fields when `Option`
  is none. Pull request by Stefan Sundin. GitHub #79.
- `Serialize` and `Clone` were added to the `Metadata` struct. Pull request by
  Stefan Sundin. GitHub #80.
- Added feature to use `simdutf8` as a faster alternative when
  `unsafe-str-decode` is too risky. Pull request by Jakub Onderka. GitHub #88.
- Minor internal refactoring and performance improvements.

## 0.24.0 - 2024-01-09

- Added the `is_anycast` field to the `Traits` struct. Pull request by Skye.
  GitHub #73.

## 0.23.0 - 2022-04-03

- Added `lookup_prefix` to return the prefix length for the network associated
  with the IP address. Pull request by Marek Vavruša. GitHub #26.

## 0.22.0 - 2022-03-23

- A `within` method has been added to the reader to allow iterating over all
  records in the database. Pull request by Ross McFarland. Github #50.
- Database structs in `maxminddb::geoip2` have been updated. Most noticeably,
  an `Enterprise` struct has been added and the `model` module has been
  replaced by `city` and `country` modules. Also, several missing fields have
  been added.
- `Mmap` is now re-exported for convenience. Pull request by zhuhaow. GitHub
  #54.
- Upgraded memmap2 dependency.

## 0.21.0 - 2021-07-20

- Reduce the amount of code generated by shrinking generic methods. Pull
  request by Markus Westerlind. GitHub #49.

## 0.20.0 - 2021-07-11

- Use `try_into` when decoding floating point values. Pull request by Sebastian
  Mayr. GitHub #47.

## 0.19.0 - 2021-06-25

- Switch from `memmap` to `memmap2`. Pull request by Gleb Pomykalov. GitHub
  #46.

## 0.18.0 - 2021-05-29

- The `memchr` crate is now used to improve the performance of finding the
  metadata start. Pull request by Markus Westerlind. GitHub #44.

## 0.17.3 - 2021-05-29

- Correct handling of pointers in the database metadata section. This bug
  caused the latest GeoIP2 ISP database from MaxMind to fail to load with an
  `InvalidDatabaseError` due to an invalid data type. Reported by
  Marwes-Imperva. GitHub #45.

## 0.17.2 - 2021-02-11

- Minor cleanup.

## 0.17.1 - 2021-01-03

- Restore compatibility with targets that don't support 128-bit integers. Pull
  request by Filip. GitHub #41.

## 0.17.0 - 2020-12-12

- Unsigned 128-bit integers are now decoded to a `u128` rather than a `[u8]`.
  Pull request by moschroe. GitHub #40.

## 0.16.0 - 2020-12-05

- This release includes major performance improvements and code cleanup. Pull
  request by Sebastian Mayr. GitHub #37.

## 0.15.0 - 2020-10-10

- Remove crate options leftover from before Rust 1.0. In particular, this crate
  no longer specifies `crate_type`. This should allow you to compile it with
  `panic = "abort"`. Reported by ye2020. GitHub #33.

## 0.14.0 - 2020-06-07

- BREAKING CHANGE: All Strings in the `geoip2` structs are not returned as
  references. This was done to provide a significant performance improvement
  when ownership is not needed. Pull request by Matthew Wynn. GitHub #31.
- A new opt-in feature, `unsafe-str-decode`, has been added that will skip
  UTF-8 validation when decoding strings. You should only use this when you
  trust that the MaxMind DB is valid and contains valid UTF-8 strings. This
  provides a modest performance improvement. Pull request by Matthew Wynn.
  GitHub #31.
- Many other internal improvements to reduce the number of allocations.

## 0.13.0 - 2019-01-21

- Missing models for `DensityIncome`, `Domain`, and `Asn` were added and the
  missing `is_in_european_union` field was added to the `Country` model. Pull
  request by Sebastian Nadorp. GitHub #19.
- More details are now included in the `Display` implementation for
  `MaxMindDBError`. Pull request by Mike Cooper. GitHub #20.

## 0.12.0 - 2018-12-09

- `Reader::open` has been removed. You should use `Reader::open_readfile` or
  `Reader::open_mmap`. Pull request by kpcyrd. GitHub #17 & #18.
- `Reader::open_readfile` no longer depends on `unsafe`. Pull request by
  kpcyrd. GitHub #17 & #18.

## 0.11.0 - 2018-11-12

- An optional `mmap` cfg feature flag has been added. When set, `open` will use
  the `memmap` crate to memory map the database file rather than reading it
  from file. In addition to `open`, `open_readfile` and `open_mmap` are
  available. PR by moschroe. GitHub #16.
- `Reader::open` now takes an `AsRef<Path>`. Also, #16.
- `Reader::from_buf` allows using an existing buffer instead of specifying a
  database file. PR by kpcyrd. GitHub #15.

## 0.10.0 - 2018-08-07

- Derive `Serialize` for GeoIP2 models. Pull request by Bryan Gilbert. GitHub
  #11.

## 0.9.0 - 2018-02-16

- Update logger to 0.4 and env_logger to 0.5.

## 0.8.1 - 2017-07-02

- Implement unimplemented deserialize methods.

## 0.8.0 - 2017-06-28

- API CHANGE: Switch to Serde for deserialization. Data structures being
  deserialized to must implement the `Deserialize` trait. Pull request by
  Wesley Moore. GitHub #5.

## 0.7.2 - 2017-04-16

- Update `log` to 0.3.7 and `rustc-serialize` to 0.3.23.

## 0.7.1 - 2016-11-13

- Update `rustc-serialize` to 0.3.21.

## 0.7.0 - 2016-05-15

- API CHANGE: `lookup` takes an `IpAddr` again instead of a `SocketAddr`. We
  previously switched to `SocketAddr` after `IpAddr` had been deprecated, but
  it has since been re-added.
