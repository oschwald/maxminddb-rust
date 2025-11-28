# Upgrading Guide

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
