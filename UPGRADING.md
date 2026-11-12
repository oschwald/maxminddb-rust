# Upgrading Guide

## 0.32 to 0.33

### Newtype Deserialization

`deserialize_newtype_struct` now calls `Visitor::visit_newtype_struct`.
Before 0.33, it decoded the inner value and passed it straight to methods
such as `visit_str` or `visit_map`. Derived newtypes such as
`struct Name(String)` now work.

If you wrote a visitor for `deserialize_newtype_struct` by hand, implement
`visit_newtype_struct` and deserialize the inner value there:

```rust
fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserializer.deserialize_str(self)
}
```

## 0.31 to 0.32

### simdutf8 Feature Removal

The `simdutf8` feature is gone. It did not speed up lookups on production
GeoIP2 City and Country databases. Cargo rejects a dependency that still
enables it, so remove it from your feature list.

**Before (0.31):**

```toml
maxminddb = { version = "0.31", features = ["simdutf8"] }
```

**After (0.32):**

```toml
maxminddb = "0.32"
```

## 0.30 to 0.31

### Decoding Resource Limits

Each record or metadata decode now has fixed limits:

- 65,536 values.
- 2 MiB of string and byte data. Data that pointers reach more than once
  counts each time.

`Reader::verify()` also limits its work. An operation that exceeds a limit
returns `MaxMindDbError::ResourceLimit`. The limits stop crafted databases
that reference shared data repeatedly. You cannot change them, so a custom
database with records above them now fails to decode.

The `geoip2::City` and `geoip2::Enterprise` types also reject records with
more than 32 subdivisions (`geoip2::MAX_SUBDIVISIONS`) with
`MaxMindDbError::Decoding`.

`MaxMindDbError` is `#[non_exhaustive]`, so existing `match` expressions
still compile. Add a `ResourceLimit` arm if you handle errors by variant.

## 0.28 to 0.29

### Reader Metadata

`Reader::metadata` is now private. Use `Reader::metadata()` to access
validated metadata by shared reference.

**Before (0.28):**

```rust
let database_type = &reader.metadata.database_type;
```

**After (0.29):**

```rust
let database_type = &reader.metadata().database_type;
```

### Metadata Build Time

`Metadata::build_time()` now returns `Result<SystemTime, MaxMindDbError>`.
Databases whose `build_epoch` cannot be represented as `SystemTime` are
rejected as invalid when opened or verified.

**Before (0.28):**

```rust
let build_time = reader.metadata.build_time();
```

**After (0.29):**

```rust
let build_time = reader.metadata().build_time()?;
```

### Metadata Validation

Opening a database now rejects unsupported major format versions, unsupported
IP versions, zero-node search trees, and unrepresentable build epochs as
invalid databases. Minor format versions are still accepted for forward
compatibility.

## 0.26 to 0.27

This release includes significant API changes to improve ergonomics and enable
new features like lazy decoding and selective field access.

### Lookup API

The `lookup()` method now returns a `LookupResult` that supports lazy decoding.

**Before (0.26):**

```rust
let city: Option<geoip2::City> = reader.lookup(ip)?;
if let Some(city) = city {
    println!("{:?}", city.city);
}
```

**After (0.27):**

```rust
let result = reader.lookup(ip)?;
if let Some(city) = result.decode::<geoip2::City>()? {
    println!("{:?}", city.city);
}
```

The new API allows you to:

- Check if data exists without decoding: `result.has_data()`
- Get the network for the IP: `result.network()?`
- Decode only specific fields: `result.decode_path(&[...])?`

### lookup_prefix Removal

The `lookup_prefix()` method has been removed. Use `lookup()` with `network()`.

**Before (0.26):**

```rust
let (city, prefix_len) = reader.lookup_prefix(ip)?;
```

**After (0.27):**

```rust
let result = reader.lookup(ip)?;
let city = result.decode::<geoip2::City>()?;
let network = result.network()?;  // Returns IpNetwork with prefix
```

### Within Iterator

The `within()` method now requires a `WithinOptions` parameter.

**Before (0.26):**

```rust
for item in reader.within::<geoip2::City>(cidr)? {
    let item = item?;
    println!("{}: {:?}", item.ip_net, item.info);
}
```

**After (0.27):**

```rust
use maxminddb::WithinOptions;

for result in reader.within(cidr, Default::default())? {
    let result = result?;
    let network = result.network()?;
    if let Some(city) = result.decode::<geoip2::City>()? {
        println!("{}: {:?}", network, city);
    }
}
```

To customize iteration behavior:

```rust
let options = WithinOptions::default()
    .include_aliased_networks()      // Include IPv4 via IPv6 aliases
    .include_networks_without_data() // Include networks without data
    .skip_empty_values();            // Skip empty maps/arrays

for result in reader.within(cidr, options)? {
    // ...
}
```

### GeoIP2 Name Fields

The `names` fields now use a `Names` struct instead of `BTreeMap`.

**Before (0.26):**

```rust
let name = city.city
    .as_ref()
    .and_then(|c| c.names.as_ref())
    .and_then(|n| n.get("en"));
```

**After (0.27):**

```rust
let name = city.city.names.english;
```

Available language fields:

- `german`
- `english`
- `spanish`
- `french`
- `japanese`
- `brazilian_portuguese`
- `russian`
- `simplified_chinese`

### GeoIP2 Nested Structs

Nested struct fields are now non-optional with `Default`.

**Before (0.26):**

```rust
let iso_code = city.country
    .as_ref()
    .and_then(|c| c.iso_code.as_ref());

let subdivisions = city.subdivisions
    .as_ref()
    .map(|v| v.iter())
    .into_iter()
    .flatten();
```

**After (0.27):**

```rust
let iso_code = city.country.iso_code;

for subdivision in &city.subdivisions {
    // ...
}
```

Leaf values (strings, numbers, bools) remain `Option<T>`.

### Removed Trait Fields

The `is_anonymous_proxy` and `is_satellite_provider` fields have been removed
from `country::Traits` and `enterprise::Traits`. These fields are no longer
present in MaxMind databases.

For anonymity detection, use the [Anonymous IP database](https://www.maxmind.com/en/geoip2-anonymous-ip-database).

### Error Types

Error variants now use structured fields.

**Before (0.26):**

```rust
match error {
    MaxMindDbError::InvalidDatabase(msg) => {
        println!("Invalid database: {}", msg);
    }
    // ...
}
```

**After (0.27):**

```rust
match error {
    MaxMindDbError::InvalidDatabase { message, offset } => {
        println!("Invalid database: {} at {:?}", message, offset);
    }
    MaxMindDbError::InvalidInput { message } => {
        println!("Invalid input: {}", message);
    }
    // ...
}
```

The new `InvalidInput` variant is used for user errors like looking up an IPv6
address in an IPv4-only database.

### Quick Migration Checklist

1. Update `lookup()` calls to use `.decode::<T>()?`
2. Replace `lookup_prefix()` with `lookup()` + `network()`
3. Add `Default::default()` as second argument to `within()`
4. Update `within()` loops to use `result.network()` and `result.decode()`
5. Replace `names.get("en")` with `names.english`
6. Remove `.as_ref()` chains for nested GeoIP2 fields
7. Remove references to `is_anonymous_proxy` and `is_satellite_provider`
8. Update error matching to use struct patterns
