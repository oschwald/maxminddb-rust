//! Lookup result types for deferred decoding.
//!
//! This module provides `LookupResult`, which enables lazy decoding of
//! MaxMind DB records. Instead of immediately deserializing data, you
//! get a lightweight handle that can be decoded later or navigated
//! selectively via paths.

use std::net::IpAddr;

use ipnetwork::IpNetwork;
use serde::Deserialize;

use super::decoder::{TYPE_ARRAY, TYPE_MAP};
use super::{MaxMindDbError, Reader};

/// The result of looking up an IP address in a MaxMind DB.
///
/// This is a lightweight handle (~40 bytes) that stores the lookup result
/// without immediately decoding the data. You can:
///
/// - Check if the IP was found with [`found()`](Self::found)
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
/// if result.found() {
///     // Full decode
///     let city: geoip2::City = result.decode().unwrap();
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
    /// Offset into the data section, or usize::MAX if not found
    data_offset: usize,
    prefix_len: u8,
    ip: IpAddr,
}

/// Not found sentinel value
const NOT_FOUND: usize = usize::MAX;

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
            data_offset,
            prefix_len,
            ip,
        }
    }

    /// Creates a new LookupResult for an IP not in the database.
    pub(crate) fn new_not_found(reader: &'a Reader<S>, prefix_len: u8, ip: IpAddr) -> Self {
        LookupResult {
            reader,
            data_offset: NOT_FOUND,
            prefix_len,
            ip,
        }
    }

    /// Returns true if the IP address was found in the database.
    ///
    /// Note that "not found" means the database has no data for this IP,
    /// which is different from an error during lookup.
    #[inline]
    pub fn found(&self) -> bool {
        self.data_offset != NOT_FOUND
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
        if self.found() {
            Some(self.data_offset)
        } else {
            None
        }
    }

    /// Decodes the full record into the specified type.
    ///
    /// Returns an error if the IP was not found or if decoding fails.
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
    /// let city: geoip2::City = result.decode().unwrap();
    /// ```
    pub fn decode<T>(&self) -> Result<T, MaxMindDbError>
    where
        T: Deserialize<'a>,
    {
        if !self.found() {
            return Err(MaxMindDbError::Decoding(
                "cannot decode: IP address not found in database".to_owned(),
            ));
        }

        let buf = &self.reader.buf.as_ref()[self.reader.pointer_base..];
        let mut decoder = super::decoder::Decoder::new(buf, self.data_offset);
        T::deserialize(&mut decoder)
    }

    /// Decodes a value at a specific path within the record.
    ///
    /// Returns:
    /// - `Ok(Some(T))` if the path exists and was successfully decoded
    /// - `Ok(None)` if the path doesn't exist (key missing, index out of bounds)
    /// - `Err(...)` if there's a type mismatch during navigation (e.g., `Key` on an array)
    ///
    /// If `found() == false`, returns `Ok(None)`.
    ///
    /// # Path Elements
    ///
    /// - `PathElement::Key("name")` - Navigate into a map by key
    /// - `PathElement::Index(0)` - Navigate into an array by index
    /// - `PathElement::Index(-1)` - Last element (Python-style negative indexing)
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
        if !self.found() {
            return Ok(None);
        }

        let buf = &self.reader.buf.as_ref()[self.reader.pointer_base..];
        let mut decoder = super::decoder::Decoder::new(buf, self.data_offset);

        // Navigate through the path
        for element in path {
            match element {
                PathElement::Key(key) => {
                    let (_, type_num) = decoder.peek_type()?;
                    if type_num != TYPE_MAP {
                        return Err(MaxMindDbError::Decoding(format!(
                            "expected map for Key navigation, got type {type_num}"
                        )));
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
                        return Err(MaxMindDbError::Decoding(format!(
                            "expected array for Index navigation, got type {type_num}"
                        )));
                    }

                    // Consume the array header and get size
                    let size = decoder.consume_array_header()?;

                    // Handle negative indexing (Python-style)
                    let actual_idx = if *idx < 0 {
                        let positive = (-*idx) as usize;
                        if positive > size {
                            return Ok(None); // Out of bounds
                        }
                        size - positive
                    } else {
                        let positive = *idx as usize;
                        if positive >= size {
                            return Ok(None); // Out of bounds
                        }
                        positive
                    };

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathElement<'a> {
    /// Navigate into a map by key.
    Key(&'a str),
    /// Navigate into an array by index.
    ///
    /// Supports Python-style negative indexing:
    /// - `Index(0)` - first element
    /// - `Index(-1)` - last element
    /// - `Index(-2)` - second-to-last element
    Index(isize),
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
        assert_eq!(format!("{:?}", PathElement::Index(-1)), "Index(-1)");
    }
}
