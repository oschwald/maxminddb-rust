//! Lookup result types for deferred decoding.
//!
//! This module provides `LookupResult`, which enables lazy decoding of
//! MaxMind DB records. Instead of immediately deserializing data, you
//! get a lightweight handle that can be decoded later or navigated
//! selectively via paths.

use std::net::IpAddr;

use ipnetwork::IpNetwork;
use serde::Deserialize;

use crate::decoder::{TYPE_ARRAY, TYPE_MAP};
use crate::error::MaxMindDbError;
use crate::reader::Reader;

/// The result of looking up an IP address in a MaxMind DB.
///
/// This is a lightweight handle (~40 bytes) that stores the lookup result
/// without immediately decoding the data. You can:
///
/// - Check if data exists with [`has_data()`](Self::has_data)
/// - Get the network containing the IP with [`network()`](Self::network)
/// - Decode the full record with [`decode()`](Self::decode)
/// - Decode a specific path with [`decode_path()`](Self::decode_path)
///
/// # Example
///
/// ```
/// use maxminddb::{Reader, geoip2, PathElement};
/// use std::net::IpAddr;
///
/// let reader = Reader::open_readfile("test-data/test-data/GeoIP2-City-Test.mmdb").unwrap();
/// let ip: IpAddr = "89.160.20.128".parse().unwrap();
///
/// let result = reader.lookup(ip).unwrap();
///
/// if result.has_data() {
///     // Full decode
///     let city: geoip2::City = result.decode().unwrap().unwrap();
///
///     // Or selective decode via path
///     let country_code: Option<String> = result.decode_path(&[
///         PathElement::Key("country"),
///         PathElement::Key("iso_code"),
///     ]).unwrap();
///     println!("Country: {:?}", country_code);
/// }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct LookupResult<'a, S: AsRef<[u8]>> {
    reader: &'a Reader<S>,
    /// Offset into the data section, or None if not found.
    data_offset: Option<usize>,
    prefix_len: u8,
    ip: IpAddr,
}

impl<'a, S: AsRef<[u8]>> LookupResult<'a, S> {
    /// Creates a new LookupResult for a found IP.
    pub(crate) fn new_found(
        reader: &'a Reader<S>,
        data_offset: usize,
        prefix_len: u8,
        ip: IpAddr,
    ) -> Self {
        LookupResult {
            reader,
            data_offset: Some(data_offset),
            prefix_len,
            ip,
        }
    }

    /// Creates a new LookupResult for an IP not in the database.
    pub(crate) fn new_not_found(reader: &'a Reader<S>, prefix_len: u8, ip: IpAddr) -> Self {
        LookupResult {
            reader,
            data_offset: None,
            prefix_len,
            ip,
        }
    }

    /// Returns true if the database contains data for this IP address.
    ///
    /// Note that `false` means the database has no data for this IP,
    /// which is different from an error during lookup.
    #[inline]
    pub fn has_data(&self) -> bool {
        self.data_offset.is_some()
    }

    /// Returns the network containing the looked-up IP address.
    ///
    /// This is the most specific network in the database that contains
    /// the IP, regardless of whether data was found.
    ///
    /// The returned network preserves the IP version of the original lookup:
    /// - IPv4 lookups return IPv4 networks (unless prefix < 96, see below)
    /// - IPv6 lookups return IPv6 networks (including IPv4-mapped addresses)
    ///
    /// Special case: If an IPv4 address is looked up in an IPv6 database but
    /// the matching record is at a prefix length < 96 (e.g., a database with
    /// no IPv4 subtree), an IPv6 network is returned since there's no valid
    /// IPv4 representation.
    pub fn network(&self) -> Result<IpNetwork, MaxMindDbError> {
        let (ip, prefix) = match self.ip {
            IpAddr::V4(v4) => {
                // For IPv4 lookups in IPv6 databases, prefix_len includes the
                // 96-bit offset. Subtract it to get the IPv4 prefix.
                // For IPv4 databases, prefix_len is already 0-32.
                if self.prefix_len >= 96 {
                    // IPv6 database: subtract 96 to get IPv4 prefix
                    (IpAddr::V4(v4), self.prefix_len - 96)
                } else if self.prefix_len > 32 {
                    // IPv6 database with record at prefix < 96 (e.g., ::/64).
                    // Return IPv6 network since there's no valid IPv4 representation.
                    use std::net::Ipv6Addr;
                    (IpAddr::V6(Ipv6Addr::UNSPECIFIED), self.prefix_len)
                } else {
                    // IPv4 database: use prefix directly
                    (IpAddr::V4(v4), self.prefix_len)
                }
            }
            IpAddr::V6(v6) => {
                // For IPv6 lookups, preserve the IPv6 form (including IPv4-mapped)
                (IpAddr::V6(v6), self.prefix_len)
            }
        };

        // Mask the IP to the network address
        let network_ip = mask_ip(ip, prefix);
        IpNetwork::new(network_ip, prefix).map_err(MaxMindDbError::InvalidNetwork)
    }

    /// Returns the data section offset if found, for use as a cache key.
    ///
    /// Multiple IP addresses often point to the same data record. This
    /// offset can be used to deduplicate decoding or cache results.
    ///
    /// Returns `None` if the IP was not found.
    #[inline]
    pub fn offset(&self) -> Option<usize> {
        self.data_offset
    }

    /// Decodes the full record into the specified type.
    ///
    /// Returns:
    /// - `Ok(Some(T))` if found and successfully decoded
    /// - `Ok(None)` if the IP was not found in the database
    /// - `Err(...)` if decoding fails
    ///
    /// # Example
    ///
    /// ```
    /// use maxminddb::{Reader, geoip2};
    /// use std::net::IpAddr;
    ///
    /// let reader = Reader::open_readfile("test-data/test-data/GeoIP2-City-Test.mmdb").unwrap();
    /// let ip: IpAddr = "89.160.20.128".parse().unwrap();
    ///
    /// let result = reader.lookup(ip).unwrap();
    /// if let Some(city) = result.decode::<geoip2::City>()? {
    ///     println!("Found city data");
    /// }
    /// # Ok::<(), maxminddb::MaxMindDbError>(())
    /// ```
    pub fn decode<T>(&self) -> Result<Option<T>, MaxMindDbError>
    where
        T: Deserialize<'a>,
    {
        let Some(offset) = self.data_offset else {
            return Ok(None);
        };

        let buf = &self.reader.buf.as_ref()[self.reader.pointer_base..];
        let mut decoder = super::decoder::Decoder::new(buf, offset);
        T::deserialize(&mut decoder).map(Some)
    }

    /// Decodes a value at a specific path within the record.
    ///
    /// Returns:
    /// - `Ok(Some(T))` if the path exists and was successfully decoded
    /// - `Ok(None)` if the path doesn't exist (key missing, index out of bounds)
    /// - `Err(...)` if there's a type mismatch during navigation (e.g., `Key` on an array)
    ///
    /// If `has_data() == false`, returns `Ok(None)`.
    ///
    /// # Path Elements
    ///
    /// - `PathElement::Key("name")` - Navigate into a map by key
    /// - `PathElement::Index(0)` - Navigate into an array by index (0 = first element)
    /// - `PathElement::IndexFromEnd(0)` - Navigate from the end (0 = last element)
    ///
    /// # Example
    ///
    /// ```
    /// use maxminddb::{Reader, PathElement};
    /// use std::net::IpAddr;
    ///
    /// let reader = Reader::open_readfile("test-data/test-data/GeoIP2-City-Test.mmdb").unwrap();
    /// let ip: IpAddr = "89.160.20.128".parse().unwrap();
    ///
    /// let result = reader.lookup(ip).unwrap();
    ///
    /// // Navigate to country.iso_code
    /// let iso_code: Option<String> = result.decode_path(&[
    ///     PathElement::Key("country"),
    ///     PathElement::Key("iso_code"),
    /// ]).unwrap();
    ///
    /// // Navigate to subdivisions[0].names.en
    /// let subdiv_name: Option<String> = result.decode_path(&[
    ///     PathElement::Key("subdivisions"),
    ///     PathElement::Index(0),
    ///     PathElement::Key("names"),
    ///     PathElement::Key("en"),
    /// ]).unwrap();
    /// ```
    pub fn decode_path<T>(&self, path: &[PathElement<'_>]) -> Result<Option<T>, MaxMindDbError>
    where
        T: Deserialize<'a>,
    {
        let Some(offset) = self.data_offset else {
            return Ok(None);
        };

        let buf = &self.reader.buf.as_ref()[self.reader.pointer_base..];
        let mut decoder = super::decoder::Decoder::new(buf, offset);

        // Navigate through the path
        for element in path {
            match element {
                PathElement::Key(key) => {
                    let (_, type_num) = decoder.peek_type()?;
                    if type_num != TYPE_MAP {
                        return Err(MaxMindDbError::decoding_at(
                            format!("expected map for Key navigation, got type {type_num}"),
                            decoder.offset(),
                        ));
                    }

                    // Consume the map header and get size
                    let size = decoder.consume_map_header()?;

                    let mut found = false;
                    for _ in 0..size {
                        let k = decoder.read_string()?;
                        if k == *key {
                            found = true;
                            break;
                        } else {
                            decoder.skip_value()?;
                        }
                    }

                    if !found {
                        return Ok(None);
                    }
                }
                PathElement::Index(idx) => {
                    let (_, type_num) = decoder.peek_type()?;
                    if type_num != TYPE_ARRAY {
                        return Err(MaxMindDbError::decoding_at(
                            format!("expected array for Index navigation, got type {type_num}"),
                            decoder.offset(),
                        ));
                    }

                    // Consume the array header and get size
                    let size = decoder.consume_array_header()?;

                    if *idx >= size {
                        return Ok(None); // Out of bounds
                    }

                    // Skip to the target index
                    for _ in 0..*idx {
                        decoder.skip_value()?;
                    }
                }
                PathElement::IndexFromEnd(idx) => {
                    let (_, type_num) = decoder.peek_type()?;
                    if type_num != TYPE_ARRAY {
                        return Err(MaxMindDbError::decoding_at(
                            format!(
                                "expected array for IndexFromEnd navigation, got type {type_num}"
                            ),
                            decoder.offset(),
                        ));
                    }

                    // Consume the array header and get size
                    let size = decoder.consume_array_header()?;

                    if *idx >= size {
                        return Ok(None); // Out of bounds
                    }

                    let actual_idx = size - 1 - *idx;

                    // Skip to the target index
                    for _ in 0..actual_idx {
                        decoder.skip_value()?;
                    }
                }
            }
        }

        // Decode the value at the current position
        T::deserialize(&mut decoder).map(Some)
    }
}

/// A path element for navigating into nested data structures.
///
/// Used with [`LookupResult::decode_path()`] to selectively decode
/// specific fields without parsing the entire record.
///
/// # Creating Path Elements
///
/// You can create path elements directly or use the [`path!`](crate::path) macro
/// for a more convenient syntax:
///
/// ```
/// use maxminddb::{path, PathElement};
///
/// // Direct construction
/// let path = [PathElement::Key("country"), PathElement::Key("iso_code")];
///
/// // Using the macro - string literals become Keys, integers become Indexes
/// let path = path!["country", "iso_code"];
/// let path = path!["subdivisions", 0, "names"];  // Mixed keys and indexes
/// let path = path!["array", -1];  // Negative indexes count from the end
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathElement<'a> {
    /// Navigate into a map by key.
    Key(&'a str),
    /// Navigate into an array by index (0-based from the start).
    ///
    /// - `Index(0)` - first element
    /// - `Index(1)` - second element
    Index(usize),
    /// Navigate into an array by index from the end.
    ///
    /// - `IndexFromEnd(0)` - last element
    /// - `IndexFromEnd(1)` - second-to-last element
    IndexFromEnd(usize),
}

impl<'a> From<&'a str> for PathElement<'a> {
    fn from(s: &'a str) -> Self {
        PathElement::Key(s)
    }
}

impl From<i32> for PathElement<'_> {
    /// Converts an integer to a path element.
    ///
    /// - Non-negative values become `Index(n)`
    /// - Negative values become `IndexFromEnd(-n - 1)`, so `-1` is the last element
    fn from(n: i32) -> Self {
        if n >= 0 {
            PathElement::Index(n as usize)
        } else {
            PathElement::IndexFromEnd((-n - 1) as usize)
        }
    }
}

impl From<usize> for PathElement<'_> {
    fn from(n: usize) -> Self {
        PathElement::Index(n)
    }
}

impl From<isize> for PathElement<'_> {
    /// Converts a signed integer to a path element.
    ///
    /// - Non-negative values become `Index(n)`
    /// - Negative values become `IndexFromEnd(-n - 1)`, so `-1` is the last element
    fn from(n: isize) -> Self {
        if n >= 0 {
            PathElement::Index(n as usize)
        } else {
            PathElement::IndexFromEnd((-n - 1) as usize)
        }
    }
}

/// Creates a path for use with [`LookupResult::decode_path()`](crate::LookupResult::decode_path).
///
/// This macro provides a convenient way to construct paths with mixed string keys
/// and integer indexes.
///
/// # Syntax
///
/// - String literals become [`PathElement::Key`]
/// - Non-negative integers become [`PathElement::Index`]
/// - Negative integers become [`PathElement::IndexFromEnd`] (e.g., `-1` is the last element)
///
/// # Examples
///
/// ```
/// use maxminddb::{Reader, path};
/// use std::net::IpAddr;
///
/// let reader = Reader::open_readfile("test-data/test-data/GeoIP2-City-Test.mmdb").unwrap();
/// let ip: IpAddr = "89.160.20.128".parse().unwrap();
/// let result = reader.lookup(ip).unwrap();
///
/// // Navigate to country.iso_code
/// let iso_code: Option<String> = result.decode_path(&path!["country", "iso_code"]).unwrap();
///
/// // Navigate to subdivisions[0].names.en
/// let subdiv: Option<String> = result.decode_path(&path!["subdivisions", 0, "names", "en"]).unwrap();
/// ```
///
/// ```
/// use maxminddb::{Reader, path};
/// use std::net::IpAddr;
///
/// let reader = Reader::open_readfile("test-data/test-data/MaxMind-DB-test-decoder.mmdb").unwrap();
/// let ip: IpAddr = "::1.1.1.0".parse().unwrap();
/// let result = reader.lookup(ip).unwrap();
///
/// // Access the last element of an array
/// let last: Option<u32> = result.decode_path(&path!["array", -1]).unwrap();
/// assert_eq!(last, Some(3));
///
/// // Access the second-to-last element
/// let second_to_last: Option<u32> = result.decode_path(&path!["array", -2]).unwrap();
/// assert_eq!(second_to_last, Some(2));
/// ```
#[macro_export]
macro_rules! path {
    ($($elem:expr),* $(,)?) => {
        [$($crate::PathElement::from($elem)),*]
    };
}

/// Masks an IP address to its network address given a prefix length.
fn mask_ip(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            if prefix >= 32 {
                IpAddr::V4(v4)
            } else {
                let int: u32 = v4.into();
                let mask = if prefix == 0 {
                    0
                } else {
                    !0u32 << (32 - prefix)
                };
                IpAddr::V4((int & mask).into())
            }
        }
        IpAddr::V6(v6) => {
            if prefix >= 128 {
                IpAddr::V6(v6)
            } else {
                let int: u128 = v6.into();
                let mask = if prefix == 0 {
                    0
                } else {
                    !0u128 << (128 - prefix)
                };
                IpAddr::V6((int & mask).into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_ipv4() {
        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        assert_eq!(mask_ip(ip, 24), "192.168.1.0".parse::<IpAddr>().unwrap());
        assert_eq!(mask_ip(ip, 16), "192.168.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(mask_ip(ip, 32), "192.168.1.100".parse::<IpAddr>().unwrap());
        assert_eq!(mask_ip(ip, 0), "0.0.0.0".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_mask_ipv6() {
        let ip: IpAddr = "2001:db8:85a3::8a2e:370:7334".parse().unwrap();
        assert_eq!(
            mask_ip(ip, 64),
            "2001:db8:85a3::".parse::<IpAddr>().unwrap()
        );
        assert_eq!(mask_ip(ip, 32), "2001:db8::".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_path_element_debug() {
        assert_eq!(format!("{:?}", PathElement::Key("test")), "Key(\"test\")");
        assert_eq!(format!("{:?}", PathElement::Index(5)), "Index(5)");
        assert_eq!(
            format!("{:?}", PathElement::IndexFromEnd(0)),
            "IndexFromEnd(0)"
        );
    }

    #[test]
    fn test_path_element_from_str() {
        let elem: PathElement = "key".into();
        assert_eq!(elem, PathElement::Key("key"));
    }

    #[test]
    fn test_path_element_from_i32() {
        // Positive values become Index
        let elem: PathElement = PathElement::from(0i32);
        assert_eq!(elem, PathElement::Index(0));

        let elem: PathElement = PathElement::from(5i32);
        assert_eq!(elem, PathElement::Index(5));

        // Negative values become IndexFromEnd
        // -1 → IndexFromEnd(0) (last element)
        let elem: PathElement = PathElement::from(-1i32);
        assert_eq!(elem, PathElement::IndexFromEnd(0));

        // -2 → IndexFromEnd(1) (second-to-last)
        let elem: PathElement = PathElement::from(-2i32);
        assert_eq!(elem, PathElement::IndexFromEnd(1));

        // -3 → IndexFromEnd(2)
        let elem: PathElement = PathElement::from(-3i32);
        assert_eq!(elem, PathElement::IndexFromEnd(2));
    }

    #[test]
    fn test_path_element_from_usize() {
        let elem: PathElement = PathElement::from(0usize);
        assert_eq!(elem, PathElement::Index(0));

        let elem: PathElement = PathElement::from(42usize);
        assert_eq!(elem, PathElement::Index(42));
    }

    #[test]
    fn test_path_element_from_isize() {
        let elem: PathElement = PathElement::from(0isize);
        assert_eq!(elem, PathElement::Index(0));

        let elem: PathElement = PathElement::from(-1isize);
        assert_eq!(elem, PathElement::IndexFromEnd(0));
    }

    #[test]
    fn test_path_macro_keys_only() {
        let p = path!["country", "iso_code"];
        assert_eq!(p.len(), 2);
        assert_eq!(p[0], PathElement::Key("country"));
        assert_eq!(p[1], PathElement::Key("iso_code"));
    }

    #[test]
    fn test_path_macro_mixed() {
        let p = path!["subdivisions", 0, "names", "en"];
        assert_eq!(p.len(), 4);
        assert_eq!(p[0], PathElement::Key("subdivisions"));
        assert_eq!(p[1], PathElement::Index(0));
        assert_eq!(p[2], PathElement::Key("names"));
        assert_eq!(p[3], PathElement::Key("en"));
    }

    #[test]
    fn test_path_macro_negative_indexes() {
        let p = path!["array", -1];
        assert_eq!(p.len(), 2);
        assert_eq!(p[0], PathElement::Key("array"));
        assert_eq!(p[1], PathElement::IndexFromEnd(0)); // last element

        let p = path!["data", -2, "value"];
        assert_eq!(p[1], PathElement::IndexFromEnd(1)); // second-to-last
    }

    #[test]
    fn test_path_macro_trailing_comma() {
        let p = path!["a", "b",];
        assert_eq!(p.len(), 2);
    }

    #[test]
    fn test_path_macro_empty() {
        let p: [PathElement; 0] = path![];
        assert_eq!(p.len(), 0);
    }
}
