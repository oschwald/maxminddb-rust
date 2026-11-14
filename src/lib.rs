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
//! - **`unsafe-str-decode`** (default: disabled): Skip UTF-8 validation
//!   when deserializing trusted database strings into Rust `str` or `String`
//!   values. Cross-runtime format adapters should prefer
//!   [`deserialize_any_with_raw_strings()`] and validate while constructing
//!   the target runtime's string type.
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
//! `Reader<S>` is `Send` when `S` is `Send`, and `Sync` when `S` is `Sync`.
//! `Reader<Vec<u8>>`, returned by [`Reader::open_readfile`], implements both:
//!
//! ```
//! fn assert_send_sync<T: Send + Sync>() {}
//! assert_send_sync::<maxminddb::Reader<Vec<u8>>>();
//! ```
//!
//! Custom sources passed to [`Reader::from_source`] determine these traits.
//! For example, a source of type `std::rc::Rc<[u8]>` makes the reader neither
//! `Send` nor `Sync`.
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

/// Internal entry points for the cargo-fuzz targets.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzzing {
    use serde::Deserialize;

    use crate::decoder::{Decoder, VerificationState};
    use crate::MaxMindDbError;

    /// Deserialize one data-section value through the Serde decoder.
    pub fn decode<'de, T>(data: &'de [u8]) -> Result<T, MaxMindDbError>
    where
        T: Deserialize<'de>,
    {
        T::deserialize(&mut Decoder::new(data, 0)).map_err(Into::into)
    }

    /// Validate one data-section value through the verification decoder.
    pub fn verify(data: &[u8]) -> Result<(), MaxMindDbError> {
        Decoder::new(data, 0)
            .skip_value_for_verification(&mut VerificationState::new(data.len()))
            .map_err(Into::into)
    }
}
