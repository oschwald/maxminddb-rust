#![deny(trivial_casts, trivial_numeric_casts, unused_import_braces)]
//! # MaxMind DB Reader
//!
//! This library reads the MaxMind DB format, including the GeoIP2 and GeoLite2 databases.
//!
//! ## Features
//!
//! This crate provides several optional features for performance and functionality:
//!
//! - **`mmap`** (default: disabled): Enable memory-mapped file access for
//!   better performance in long-running applications
//! - **`simdutf8`** (default: disabled): Use SIMD instructions for faster
//!   UTF-8 validation during string decoding
//! - **`unsafe-str-decode`** (default: disabled): Skip UTF-8 validation
//!   when deserializing trusted database strings into Rust `str` or `String`
//!   values. Cross-runtime format adapters should prefer
//!   [`deserialize_any_with_raw_strings()`] and validate while constructing
//!   the target runtime's string type.
//!
//! **Note**: `simdutf8` and `unsafe-str-decode` are mutually exclusive.
//!
//! ## Database Compatibility
//!
//! This library supports all MaxMind DB format databases:
//! - **GeoIP2** databases (City, Country, Enterprise, ISP, etc.)
//! - **GeoLite2** databases (free versions)
//! - Custom MaxMind DB format databases
//!
//! ## Thread Safety
//!
//! The `Reader` is `Send` and `Sync`, making it safe to share across threads.
//! This makes it ideal for web servers and other concurrent applications.
//!
//! ## Quick Start
//!
//! ```rust
//! use maxminddb::{Reader, geoip2};
//! use std::net::IpAddr;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Open database file
//! #   let reader = Reader::open_readfile("test-data/test-data/GeoIP2-City-Test.mmdb")?;
//! #   /*
//!     let reader = Reader::open_readfile("/path/to/GeoIP2-City.mmdb")?;
//! #   */
//!
//!     // Look up an IP address
//!     let ip: IpAddr = "89.160.20.128".parse()?;
//!     let result = reader.lookup(ip)?;
//!
//!     if let Some(city) = result.decode::<geoip2::City>()? {
//!         // Access nested structs directly - no Option unwrapping needed
//!         println!("Country: {}", city.country.iso_code.unwrap_or("Unknown"));
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Selective Field Access
//!
//! Use `decode_path` to extract specific fields without deserializing the entire record:
//!
//! ```rust
//! use maxminddb::{path, Reader};
//! use std::net::IpAddr;
//!
//! let reader = Reader::open_readfile("test-data/test-data/GeoIP2-City-Test.mmdb").unwrap();
//! let ip: IpAddr = "89.160.20.128".parse().unwrap();
//!
//! let result = reader.lookup(ip).unwrap();
//! let country_code: Option<String> = result.decode_path(&path!["country", "iso_code"]).unwrap();
//!
//! println!("Country: {:?}", country_code);
//! ```

#[cfg(all(feature = "simdutf8", feature = "unsafe-str-decode"))]
compile_error!("features `simdutf8` and `unsafe-str-decode` are mutually exclusive");

mod decoder;
mod error;
pub mod geoip2;
mod metadata;
mod reader;
mod result;
mod within;

// Re-export public types
pub use decoder::deserialize_any_with_raw_strings;
pub use error::MaxMindDbError;
pub use metadata::Metadata;
pub use reader::Reader;
pub use result::{LookupResult, PathElement};
pub use within::{Within, WithinOptions};

#[cfg(feature = "mmap")]
pub use memmap2::Mmap;

#[cfg(test)]
mod reader_test;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_lookup_network() {
        use std::collections::HashMap;

        struct TestCase {
            ip: &'static str,
            db_file: &'static str,
            expected_network: &'static str,
            expected_found: bool,
        }

        let test_cases = [
            // IPv4 address in IPv6 database - not found, returns containing network
            TestCase {
                ip: "1.1.1.1",
                db_file: "test-data/test-data/MaxMind-DB-test-ipv6-32.mmdb",
                expected_network: "1.0.0.0/8",
                expected_found: false,
            },
            // IPv6 exact match
            TestCase {
                ip: "::1:ffff:ffff",
                db_file: "test-data/test-data/MaxMind-DB-test-ipv6-24.mmdb",
                expected_network: "::1:ffff:ffff/128",
                expected_found: true,
            },
            // IPv6 network match (not exact)
            TestCase {
                ip: "::2:0:1",
                db_file: "test-data/test-data/MaxMind-DB-test-ipv6-24.mmdb",
                expected_network: "::2:0:0/122",
                expected_found: true,
            },
            // IPv4 exact match
            TestCase {
                ip: "1.1.1.1",
                db_file: "test-data/test-data/MaxMind-DB-test-ipv4-24.mmdb",
                expected_network: "1.1.1.1/32",
                expected_found: true,
            },
            // IPv4 network match (not exact)
            TestCase {
                ip: "1.1.1.3",
                db_file: "test-data/test-data/MaxMind-DB-test-ipv4-24.mmdb",
                expected_network: "1.1.1.2/31",
                expected_found: true,
            },
            // IPv4 in decoder test database
            TestCase {
                ip: "1.1.1.3",
                db_file: "test-data/test-data/MaxMind-DB-test-decoder.mmdb",
                expected_network: "1.1.1.0/24",
                expected_found: true,
            },
            // IPv4-mapped IPv6 address - preserves IPv6 form
            TestCase {
                ip: "::ffff:1.1.1.128",
                db_file: "test-data/test-data/MaxMind-DB-test-decoder.mmdb",
                expected_network: "::ffff:1.1.1.0/120",
                expected_found: true,
            },
            // IPv4-compatible IPv6 address - uses compressed IPv6 notation
            TestCase {
                ip: "::1.1.1.128",
                db_file: "test-data/test-data/MaxMind-DB-test-decoder.mmdb",
                expected_network: "::101:100/120",
                expected_found: true,
            },
            // No IPv4 search tree - IPv4 address returns ::/64
            TestCase {
                ip: "200.0.2.1",
                db_file: "test-data/test-data/MaxMind-DB-no-ipv4-search-tree.mmdb",
                expected_network: "::/64",
                expected_found: true,
            },
            // No IPv4 search tree - IPv6 address in IPv4 range
            TestCase {
                ip: "::200.0.2.1",
                db_file: "test-data/test-data/MaxMind-DB-no-ipv4-search-tree.mmdb",
                expected_network: "::/64",
                expected_found: true,
            },
            // No IPv4 search tree - IPv6 address at boundary of IPv4 space
            TestCase {
                ip: "0:0:0:0:ffff:ffff:ffff:ffff",
                db_file: "test-data/test-data/MaxMind-DB-no-ipv4-search-tree.mmdb",
                expected_network: "::/64",
                expected_found: true,
            },
            // No IPv4 search tree - high IPv6 address not found
            TestCase {
                ip: "ef00::",
                db_file: "test-data/test-data/MaxMind-DB-no-ipv4-search-tree.mmdb",
                expected_network: "8000::/1",
                expected_found: false,
            },
        ];

        // Cache readers to avoid reopening the same file multiple times
        let mut readers: HashMap<&str, Reader<Vec<u8>>> = HashMap::new();

        for test in &test_cases {
            let reader = readers
                .entry(test.db_file)
                .or_insert_with(|| Reader::open_readfile(test.db_file).unwrap());

            let ip: IpAddr = test.ip.parse().unwrap();
            let result = reader.lookup(ip).unwrap();

            assert_eq!(
                result.has_data(),
                test.expected_found,
                "IP {} in {}: expected has_data={}, got has_data={}",
                test.ip,
                test.db_file,
                test.expected_found,
                result.has_data()
            );

            let network = result.network().unwrap();
            assert_eq!(
                network.to_string(),
                test.expected_network,
                "IP {} in {}: expected network {}, got {}",
                test.ip,
                test.db_file,
                test.expected_network,
                network
            );
        }
    }

    #[test]
    fn test_lookup_with_geoip_data() {
        let reader = Reader::open_readfile("test-data/test-data/GeoIP2-City-Test.mmdb").unwrap();
        let ip: IpAddr = "89.160.20.128".parse().unwrap();

        let result = reader.lookup(ip).unwrap();
        assert!(result.has_data(), "lookup should find known IP");

        // Decode the data
        let city: geoip2::City = result.decode().unwrap().unwrap();
        assert!(!city.city.is_empty(), "Expected city data");

        // Check full network (not just prefix)
        let network = result.network().unwrap();
        assert_eq!(
            network.to_string(),
            "89.160.20.128/25",
            "Expected network 89.160.20.128/25"
        );

        // Check offset is available for caching
        assert!(
            result.offset().is_some(),
            "Expected offset to be Some for found IP"
        );
    }

    #[test]
    fn test_lookup_network_uses_measured_ipv4_subtree_depth() {
        let mut reader =
            Reader::open_readfile("test-data/test-data/MaxMind-DB-test-ipv6-32.mmdb").unwrap();
        assert_eq!(reader.metadata().ip_version, 6);

        // Simulate a valid IPv6 database whose IPv4 subtree starts somewhere
        // other than bit 96. Using a shallow subtree depth keeps the combined
        // prefix length <= 32, which would be ambiguous without an explicit
        // Lookup vs Iter source flag.
        reader.ipv4_start_bit_depth = 16;

        let result = reader.lookup("1.1.1.1".parse().unwrap()).unwrap();
        assert_eq!(result.network().unwrap().to_string(), "1.0.0.0/8");
    }

    #[test]
    fn test_lookup_offset_is_stable_for_shared_record() {
        let reader = Reader::open_readfile("test-data/test-data/GeoIP2-City-Test.mmdb").unwrap();

        let first = reader.lookup("89.160.20.128".parse().unwrap()).unwrap();
        let second = reader.lookup("89.160.20.129".parse().unwrap()).unwrap();

        assert!(first.has_data());
        assert!(second.has_data());
        assert_eq!(first.network().unwrap(), second.network().unwrap());
        assert_eq!(
            first.offset(),
            second.offset(),
            "IPs in the same record should share a cacheable offset"
        );
    }

    #[test]
    fn test_decode_path() {
        let reader = Reader::open_readfile("test-data/test-data/GeoIP2-City-Test.mmdb").unwrap();
        let ip: IpAddr = "89.160.20.128".parse().unwrap();

        let result = reader.lookup(ip).unwrap();

        // Navigate to country.iso_code
        let iso_code: Option<String> = result
            .decode_path(&[PathElement::Key("country"), PathElement::Key("iso_code")])
            .unwrap();
        assert_eq!(iso_code, Some("SE".to_owned()));

        // Navigate to non-existent path
        let missing: Option<String> = result
            .decode_path(&[PathElement::Key("nonexistent")])
            .unwrap();
        assert!(missing.is_none());
    }

    #[test]
    fn test_decode_path_on_not_found_lookup() {
        let reader = Reader::open_readfile("test-data/test-data/GeoIP2-City-Test.mmdb").unwrap();
        let ip: IpAddr = "2c0f:ff00::1".parse().unwrap();

        let result = reader.lookup(ip).unwrap();

        assert!(!result.has_data());
        assert!(result.offset().is_none());
        assert!(result.decode::<geoip2::City>().unwrap().is_none());

        let country_code: Option<String> = result
            .decode_path(&[PathElement::Key("country"), PathElement::Key("iso_code")])
            .unwrap();
        assert!(country_code.is_none());
    }

    #[test]
    fn test_ipv6_in_ipv4_database() {
        let reader =
            Reader::open_readfile("test-data/test-data/MaxMind-DB-test-ipv4-24.mmdb").unwrap();
        let ip: IpAddr = "2001::".parse().unwrap();

        let result = reader.lookup(ip);
        match result {
            Err(MaxMindDbError::InvalidInput { message }) => {
                assert!(
                    message.contains("IPv6") && message.contains("IPv4"),
                    "Expected error message about IPv6 in IPv4 database, got: {}",
                    message
                );
            }
            Err(e) => panic!(
                "Expected InvalidInput error for IPv6 in IPv4 database, got: {:?}",
                e
            ),
            Ok(_) => panic!("Expected error for IPv6 lookup in IPv4-only database"),
        }
    }

    #[test]
    fn test_decode_path_comprehensive() {
        let reader =
            Reader::open_readfile("test-data/test-data/MaxMind-DB-test-decoder.mmdb").unwrap();
        let ip: IpAddr = "::1.1.1.0".parse().unwrap();

        let result = reader.lookup(ip).unwrap();
        assert!(result.has_data());

        // Test simple path: uint16
        let u16_val: Option<u16> = result.decode_path(&[PathElement::Key("uint16")]).unwrap();
        assert_eq!(u16_val, Some(100));

        // Test array access: first element
        let arr_first: Option<u32> = result
            .decode_path(&[PathElement::Key("array"), PathElement::Index(0)])
            .unwrap();
        assert_eq!(arr_first, Some(1));

        // Test array access: last element (index 2)
        let arr_last: Option<u32> = result
            .decode_path(&[PathElement::Key("array"), PathElement::Index(2)])
            .unwrap();
        assert_eq!(arr_last, Some(3));

        // Test array access: out of bounds (index 3) returns None
        let arr_oob: Option<u32> = result
            .decode_path(&[PathElement::Key("array"), PathElement::Index(3)])
            .unwrap();
        assert!(arr_oob.is_none());

        // Test IndexFromEnd: 0 means last element
        let arr_last: Option<u32> = result
            .decode_path(&[PathElement::Key("array"), PathElement::IndexFromEnd(0)])
            .unwrap();
        assert_eq!(arr_last, Some(3));

        // Test IndexFromEnd: 2 means first element (array has 3 elements)
        let arr_first: Option<u32> = result
            .decode_path(&[PathElement::Key("array"), PathElement::IndexFromEnd(2)])
            .unwrap();
        assert_eq!(arr_first, Some(1));

        // Test nested path: map.mapX.arrayX[1]
        let nested: Option<u32> = result
            .decode_path(&[
                PathElement::Key("map"),
                PathElement::Key("mapX"),
                PathElement::Key("arrayX"),
                PathElement::Index(1),
            ])
            .unwrap();
        assert_eq!(nested, Some(8));

        // Test non-existent key returns None
        let missing: Option<u32> = result
            .decode_path(&[PathElement::Key("does-not-exist"), PathElement::Index(1)])
            .unwrap();
        assert!(missing.is_none());

        // Test utf8_string path
        let utf8: Option<String> = result
            .decode_path(&[PathElement::Key("utf8_string")])
            .unwrap();
        assert_eq!(utf8, Some("unicode! ☯ - ♫".to_owned()));
    }
}
