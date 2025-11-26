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
//!   entirely for maximum performance (~20% faster lookups)
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
//!     if result.found() {
//!         let city: geoip2::City = result.decode()?;
//!         if let Some(country) = city.country {
//!             println!("Country: {}", country.iso_code.unwrap_or("Unknown"));
//!         }
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
//! use maxminddb::{Reader, PathElement};
//! use std::net::IpAddr;
//!
//! let reader = Reader::open_readfile("test-data/test-data/GeoIP2-City-Test.mmdb").unwrap();
//! let ip: IpAddr = "89.160.20.128".parse().unwrap();
//!
//! let result = reader.lookup(ip).unwrap();
//! let country_code: Option<String> = result.decode_path(&[
//!     PathElement::Key("country"),
//!     PathElement::Key("iso_code"),
//! ]).unwrap();
//!
//! println!("Country: {:?}", country_code);
//! ```

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt::Display;
use std::fs;
use std::io;
use std::net::IpAddr;
use std::path::Path;

use ipnetwork::{IpNetwork, IpNetworkError};
use serde::{de, Deserialize, Serialize};
use thiserror::Error;

#[cfg(feature = "mmap")]
pub use memmap2::Mmap;
#[cfg(feature = "mmap")]
use memmap2::MmapOptions;
#[cfg(feature = "mmap")]
use std::fs::File;

#[cfg(all(feature = "simdutf8", feature = "unsafe-str-decode"))]
compile_error!("features `simdutf8` and `unsafe-str-decode` are mutually exclusive");

#[derive(Error, Debug)]
pub enum MaxMindDbError {
    #[error("Invalid database: {0}")]
    InvalidDatabase(String),

    #[error("I/O error: {0}")]
    Io(
        #[from]
        #[source]
        io::Error,
    ),

    #[cfg(feature = "mmap")]
    #[error("Memory map error: {0}")]
    Mmap(#[source] io::Error),

    #[error("Decoding error: {0}")]
    Decoding(String),

    #[error("Invalid network: {0}")]
    InvalidNetwork(
        #[from]
        #[source]
        IpNetworkError,
    ),
}

impl de::Error for MaxMindDbError {
    fn custom<T: Display>(msg: T) -> Self {
        MaxMindDbError::Decoding(format!("{msg}"))
    }
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Metadata {
    pub binary_format_major_version: u16,
    pub binary_format_minor_version: u16,
    pub build_epoch: u64,
    pub database_type: String,
    pub description: BTreeMap<String, String>,
    pub ip_version: u16,
    pub languages: Vec<String>,
    pub node_count: u32,
    pub record_size: u16,
}

#[derive(Debug)]
struct WithinNode {
    node: usize,
    ip_int: IpInt,
    prefix_len: usize,
}

/// Iterator over IP networks within a CIDR range.
///
/// This iterator yields [`LookupResult`] for each network in the database
/// that falls within the specified CIDR range. Use [`LookupResult::decode()`]
/// to deserialize the data for each result.
#[derive(Debug)]
pub struct Within<'de, S: AsRef<[u8]>> {
    reader: &'de Reader<S>,
    node_count: usize,
    stack: Vec<WithinNode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpInt {
    V4(u32),
    V6(u128),
}

impl IpInt {
    fn new(ip_addr: IpAddr) -> Self {
        match ip_addr {
            IpAddr::V4(v4) => IpInt::V4(v4.into()),
            IpAddr::V6(v6) => IpInt::V6(v6.into()),
        }
    }

    #[inline(always)]
    fn get_bit(&self, index: usize) -> bool {
        match self {
            IpInt::V4(ip) => (ip >> (31 - index)) & 1 == 1,
            IpInt::V6(ip) => (ip >> (127 - index)) & 1 == 1,
        }
    }

    fn bit_count(&self) -> usize {
        match self {
            IpInt::V4(_) => 32,
            IpInt::V6(_) => 128,
        }
    }

    fn is_ipv4_in_ipv6(&self) -> bool {
        match self {
            IpInt::V4(_) => false,
            IpInt::V6(ip) => *ip <= 0xFFFFFFFF,
        }
    }
}

impl<'de, S: AsRef<[u8]>> Iterator for Within<'de, S> {
    type Item = Result<LookupResult<'de, S>, MaxMindDbError>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(current) = self.stack.pop() {
            let bit_count = current.ip_int.bit_count();

            // Skip networks that are aliases for the IPv4 network
            if self.reader.ipv4_start != 0
                && current.node == self.reader.ipv4_start
                && bit_count == 128
                && !current.ip_int.is_ipv4_in_ipv6()
            {
                continue;
            }

            match current.node.cmp(&self.node_count) {
                Ordering::Greater => {
                    // This is a data node, emit it and we're done (until the following next call)
                    let ip_addr = ip_int_to_addr(&current.ip_int);

                    // Resolve the pointer to a data offset
                    let data_offset = match self.reader.resolve_data_pointer(current.node) {
                        Ok(offset) => offset,
                        Err(e) => return Some(Err(e)),
                    };

                    return Some(Ok(LookupResult::new_found(
                        self.reader,
                        data_offset,
                        current.prefix_len as u8,
                        ip_addr,
                    )));
                }
                Ordering::Equal => {
                    // Dead end, nothing to do
                }
                Ordering::Less => {
                    // In order traversal of our children
                    // right/1-bit
                    let mut right_ip_int = current.ip_int;

                    if current.prefix_len < bit_count {
                        let bit = current.prefix_len;
                        match &mut right_ip_int {
                            IpInt::V4(ip) => *ip |= 1 << (31 - bit),
                            IpInt::V6(ip) => *ip |= 1 << (127 - bit),
                        };
                    }

                    let node = match self.reader.read_node(current.node, 1) {
                        Ok(node) => node,
                        Err(e) => return Some(Err(e)),
                    };
                    self.stack.push(WithinNode {
                        node,
                        ip_int: right_ip_int,
                        prefix_len: current.prefix_len + 1,
                    });
                    // left/0-bit
                    let node = match self.reader.read_node(current.node, 0) {
                        Ok(node) => node,
                        Err(e) => return Some(Err(e)),
                    };
                    self.stack.push(WithinNode {
                        node,
                        ip_int: current.ip_int,
                        prefix_len: current.prefix_len + 1,
                    });
                }
            }
        }
        None
    }
}

/// Convert IpInt to IpAddr
fn ip_int_to_addr(ip_int: &IpInt) -> IpAddr {
    match ip_int {
        IpInt::V4(ip) => IpAddr::V4((*ip).into()),
        IpInt::V6(ip) => {
            // Check if this is an IPv4-mapped IPv6 address
            if *ip <= 0xFFFFFFFF {
                IpAddr::V4((*ip as u32).into())
            } else {
                IpAddr::V6((*ip).into())
            }
        }
    }
}

/// A reader for the MaxMind DB format. The lifetime `'data` is tied to the
/// lifetime of the underlying buffer holding the contents of the database file.
///
/// The `Reader` supports both file-based and memory-mapped access to MaxMind
/// DB files, including GeoIP2 and GeoLite2 databases.
///
/// # Features
///
/// - **`mmap`**: Enable memory-mapped file access for better performance
/// - **`simdutf8`**: Use SIMD-accelerated UTF-8 validation (faster string
///   decoding)
/// - **`unsafe-str-decode`**: Skip UTF-8 validation entirely (unsafe, but
///   ~20% faster)
#[derive(Debug)]
pub struct Reader<S: AsRef<[u8]>> {
    buf: S,
    pub metadata: Metadata,
    ipv4_start: usize,
    /// Bit depth at which ipv4_start was found (0-96). Used to calculate
    /// correct prefix lengths for IPv4 lookups in IPv6 databases.
    ipv4_start_bit_depth: usize,
    pointer_base: usize,
}

#[cfg(feature = "mmap")]
impl Reader<Mmap> {
    /// Open a MaxMind DB database file by memory mapping it.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "mmap")]
    /// # {
    /// let reader = maxminddb::Reader::open_mmap("test-data/test-data/GeoIP2-City-Test.mmdb").unwrap();
    /// # }
    /// ```
    pub fn open_mmap<P: AsRef<Path>>(database: P) -> Result<Reader<Mmap>, MaxMindDbError> {
        let file_read = File::open(database)?;
        let mmap = unsafe { MmapOptions::new().map(&file_read) }.map_err(MaxMindDbError::Mmap)?;
        Reader::from_source(mmap)
    }
}

impl Reader<Vec<u8>> {
    /// Open a MaxMind DB database file by loading it into memory.
    ///
    /// # Example
    ///
    /// ```
    /// let reader = maxminddb::Reader::open_readfile(
    ///     "test-data/test-data/GeoIP2-City-Test.mmdb").unwrap();
    /// ```
    pub fn open_readfile<P: AsRef<Path>>(database: P) -> Result<Reader<Vec<u8>>, MaxMindDbError> {
        let buf: Vec<u8> = fs::read(&database)?; // IO error converted via #[from]
        Reader::from_source(buf)
    }
}

impl<'de, S: AsRef<[u8]>> Reader<S> {
    /// Open a MaxMind DB database from anything that implements AsRef<[u8]>
    ///
    /// # Example
    ///
    /// ```
    /// use std::fs;
    /// let buf = fs::read("test-data/test-data/GeoIP2-City-Test.mmdb").unwrap();
    /// let reader = maxminddb::Reader::from_source(buf).unwrap();
    /// ```
    pub fn from_source(buf: S) -> Result<Reader<S>, MaxMindDbError> {
        let data_section_separator_size = 16;

        let metadata_start = find_metadata_start(buf.as_ref())?;
        let mut type_decoder = decoder::Decoder::new(&buf.as_ref()[metadata_start..], 0);
        let metadata = Metadata::deserialize(&mut type_decoder)?;

        let search_tree_size = (metadata.node_count as usize) * (metadata.record_size as usize) / 4;

        let mut reader = Reader {
            buf,
            pointer_base: search_tree_size + data_section_separator_size,
            metadata,
            ipv4_start: 0,
            ipv4_start_bit_depth: 0,
        };
        let (ipv4_start, ipv4_start_bit_depth) = reader.find_ipv4_start()?;
        reader.ipv4_start = ipv4_start;
        reader.ipv4_start_bit_depth = ipv4_start_bit_depth;

        Ok(reader)
    }

    /// Lookup an IP address in the database.
    ///
    /// Returns a [`LookupResult`] that can be used to:
    /// - Check if the IP was found with [`found()`](LookupResult::found)
    /// - Get the network containing the IP with [`network()`](LookupResult::network)
    /// - Decode the full record with [`decode()`](LookupResult::decode)
    /// - Decode a specific path with [`decode_path()`](LookupResult::decode_path)
    /// - Get a low-level decoder with [`decoder()`](LookupResult::decoder)
    ///
    /// # Examples
    ///
    /// Basic city lookup:
    /// ```
    /// # use maxminddb::geoip2;
    /// # use std::net::IpAddr;
    /// # fn main() -> Result<(), maxminddb::MaxMindDbError> {
    /// let reader = maxminddb::Reader::open_readfile(
    ///     "test-data/test-data/GeoIP2-City-Test.mmdb")?;
    ///
    /// let ip: IpAddr = "89.160.20.128".parse().unwrap();
    /// let result = reader.lookup(ip)?;
    ///
    /// if result.found() {
    ///     let city: geoip2::City = result.decode()?;
    ///     if let Some(city_info) = city.city {
    ///         if let Some(names) = city_info.names {
    ///             if let Some(name) = names.get("en") {
    ///                 println!("City: {}", name);
    ///             }
    ///         }
    ///     }
    /// } else {
    ///     println!("No data found for IP {}", ip);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Selective field access:
    /// ```
    /// # use maxminddb::{Reader, PathElement};
    /// # use std::net::IpAddr;
    /// # fn main() -> Result<(), maxminddb::MaxMindDbError> {
    /// let reader = Reader::open_readfile(
    ///     "test-data/test-data/GeoIP2-City-Test.mmdb")?;
    /// let ip: IpAddr = "89.160.20.128".parse().unwrap();
    ///
    /// let result = reader.lookup(ip)?;
    /// let country_code: Option<String> = result.decode_path(&[
    ///     PathElement::Key("country"),
    ///     PathElement::Key("iso_code"),
    /// ])?;
    ///
    /// println!("Country: {:?}", country_code);
    /// # Ok(())
    /// # }
    /// ```
    pub fn lookup(&'de self, address: IpAddr) -> Result<LookupResult<'de, S>, MaxMindDbError> {
        // Check for IPv6 address in IPv4-only database
        if matches!(address, IpAddr::V6(_)) && self.metadata.ip_version == 4 {
            return Err(MaxMindDbError::InvalidDatabase(
                "you attempted to look up an IPv6 address in an IPv4-only database".to_string(),
            ));
        }

        let ip_int = IpInt::new(address);
        let (pointer, prefix_len) = self.find_address_in_tree(&ip_int)?;

        // For IPv4 addresses in IPv6 databases, adjust prefix_len to reflect
        // the actual bit depth in the tree. The ipv4_start_bit_depth tells us
        // how deep in the IPv6 tree we were when we found the IPv4 subtree.
        let prefix_len = if matches!(address, IpAddr::V4(_)) && self.metadata.ip_version == 6 {
            self.ipv4_start_bit_depth + prefix_len
        } else {
            prefix_len
        };

        if pointer == 0 {
            // IP not found in database
            Ok(LookupResult::new_not_found(self, prefix_len as u8, address))
        } else {
            // Resolve the pointer to a data offset
            let data_offset = self.resolve_data_pointer(pointer)?;
            Ok(LookupResult::new_found(
                self,
                data_offset,
                prefix_len as u8,
                address,
            ))
        }
    }

    /// Iterate over IP networks within a CIDR range.
    ///
    /// Returns an iterator that yields [`LookupResult`] for each network in the
    /// database that falls within the specified CIDR range.
    ///
    /// # Examples
    ///
    /// Iterate over all IPv4 networks:
    /// ```
    /// use ipnetwork::IpNetwork;
    /// use maxminddb::{geoip2, Reader};
    ///
    /// let reader = Reader::open_readfile(
    ///     "test-data/test-data/GeoIP2-City-Test.mmdb").unwrap();
    ///
    /// let ipv4_all = IpNetwork::V4("0.0.0.0/0".parse().unwrap());
    /// let mut count = 0;
    /// for result in reader.within(ipv4_all).unwrap() {
    ///     let lookup = result.unwrap();
    ///     let network = lookup.network().unwrap();
    ///     let city: geoip2::City = lookup.decode().unwrap();
    ///     let city_name = city.city.as_ref()
    ///         .and_then(|c| c.names.as_ref())
    ///         .and_then(|n| n.get("en"));
    ///     println!("Network: {}, City: {:?}", network, city_name);
    ///     count += 1;
    ///     if count >= 10 { break; } // Limit output for example
    /// }
    /// ```
    ///
    /// Search within a specific subnet:
    /// ```
    /// use ipnetwork::IpNetwork;
    /// use maxminddb::{geoip2, Reader};
    ///
    /// let reader = Reader::open_readfile(
    ///     "test-data/test-data/GeoIP2-City-Test.mmdb").unwrap();
    ///
    /// let subnet = IpNetwork::V4("192.168.0.0/16".parse().unwrap());
    /// for result in reader.within(subnet).unwrap() {
    ///     match result {
    ///         Ok(lookup) => {
    ///             let network = lookup.network().unwrap();
    ///             println!("Found: {}", network);
    ///         }
    ///         Err(e) => eprintln!("Error: {}", e),
    ///     }
    /// }
    /// ```
    pub fn within(&'de self, cidr: IpNetwork) -> Result<Within<'de, S>, MaxMindDbError> {
        let ip_address = cidr.network();
        let prefix_len = cidr.prefix() as usize;
        let ip_int = IpInt::new(ip_address);
        let bit_count = ip_int.bit_count();

        let mut node = self.start_node(bit_count);
        let node_count = self.metadata.node_count as usize;

        let mut stack: Vec<WithinNode> = Vec::with_capacity(bit_count - prefix_len);

        // Traverse down the tree to the level that matches the cidr mark
        let mut i = 0_usize;
        while i < prefix_len {
            let bit = ip_int.get_bit(i);
            node = self.read_node(node, bit as usize)?;
            if node >= node_count {
                // We've hit a dead end before we exhausted our prefix
                break;
            }

            i += 1;
        }

        if node < node_count {
            // Ok, now anything that's below node in the tree is "within", start with the node we
            // traversed to as our to be processed stack.
            stack.push(WithinNode {
                node,
                ip_int,
                prefix_len,
            });
        }
        // else the stack will be empty and we'll be returning an iterator that visits nothing,
        // which makes sense.

        let within = Within {
            reader: self,
            node_count,
            stack,
        };

        Ok(within)
    }

    fn find_address_in_tree(&self, ip_int: &IpInt) -> Result<(usize, usize), MaxMindDbError> {
        let bit_count = ip_int.bit_count();
        let mut node = self.start_node(bit_count);

        let node_count = self.metadata.node_count as usize;
        let mut prefix_len = bit_count;

        for i in 0..bit_count {
            if node >= node_count {
                prefix_len = i;
                break;
            }
            let bit = ip_int.get_bit(i);
            node = self.read_node(node, bit as usize)?;
        }
        match node_count {
            // If node == node_count, it means we hit the placeholder "empty" node
            // return 0 as the pointer value to signify "not found".
            n if n == node => Ok((0, prefix_len)),
            n if node > n => Ok((node, prefix_len)),
            _ => Err(MaxMindDbError::InvalidDatabase(
                "invalid node in search tree".to_owned(),
            )),
        }
    }

    #[inline]
    fn start_node(&self, length: usize) -> usize {
        if length == 128 {
            0
        } else {
            self.ipv4_start
        }
    }

    /// Find the IPv4 start node and the bit depth at which it was found.
    /// Returns (node, depth) where depth is how far into the tree we traversed.
    fn find_ipv4_start(&self) -> Result<(usize, usize), MaxMindDbError> {
        if self.metadata.ip_version != 6 {
            return Ok((0, 0));
        }

        // We are looking up an IPv4 address in an IPv6 tree. Skip over the
        // first 96 nodes.
        let mut node: usize = 0_usize;
        let mut depth: usize = 0;
        for i in 0_u8..96 {
            if node >= self.metadata.node_count as usize {
                depth = i as usize;
                break;
            }
            node = self.read_node(node, 0)?;
            depth = (i + 1) as usize;
        }
        Ok((node, depth))
    }

    #[inline(always)]
    fn read_node(&self, node_number: usize, index: usize) -> Result<usize, MaxMindDbError> {
        let buf = self.buf.as_ref();
        let base_offset = node_number * (self.metadata.record_size as usize) / 4;

        let val = match self.metadata.record_size {
            24 => {
                let offset = base_offset + index * 3;
                (buf[offset] as usize) << 16
                    | (buf[offset + 1] as usize) << 8
                    | buf[offset + 2] as usize
            }
            28 => {
                let middle = if index != 0 {
                    buf[base_offset + 3] & 0x0F
                } else {
                    (buf[base_offset + 3] & 0xF0) >> 4
                };
                let offset = base_offset + index * 4;
                (middle as usize) << 24
                    | (buf[offset] as usize) << 16
                    | (buf[offset + 1] as usize) << 8
                    | buf[offset + 2] as usize
            }
            32 => {
                let offset = base_offset + index * 4;
                (buf[offset] as usize) << 24
                    | (buf[offset + 1] as usize) << 16
                    | (buf[offset + 2] as usize) << 8
                    | buf[offset + 3] as usize
            }
            s => {
                return Err(MaxMindDbError::InvalidDatabase(format!(
                    "unknown record size: \
                     {s:?}"
                )))
            }
        };
        Ok(val)
    }

    /// Resolves a pointer from the search tree to an offset in the data section.
    #[inline]
    fn resolve_data_pointer(&self, pointer: usize) -> Result<usize, MaxMindDbError> {
        let resolved = pointer - (self.metadata.node_count as usize) - 16;

        // Check bounds using pointer_base which marks the start of the data section
        if resolved >= (self.buf.as_ref().len() - self.pointer_base) {
            return Err(MaxMindDbError::InvalidDatabase(
                "the MaxMind DB file's data pointer resolves to an invalid location".to_owned(),
            ));
        }

        Ok(resolved)
    }
}

fn find_metadata_start(buf: &[u8]) -> Result<usize, MaxMindDbError> {
    const METADATA_START_MARKER: &[u8] = b"\xab\xcd\xefMaxMind.com";

    memchr::memmem::rfind(buf, METADATA_START_MARKER)
        .map(|x| x + METADATA_START_MARKER.len())
        .ok_or_else(|| {
            MaxMindDbError::InvalidDatabase(
                "Could not find MaxMind DB metadata in file.".to_owned(),
            )
        })
}

mod decoder;
pub mod geoip2;
mod result;

pub use result::{LookupResult, PathElement};

#[cfg(test)]
mod reader_test;

#[cfg(test)]
mod tests {
    use super::MaxMindDbError;
    use ipnetwork::IpNetworkError;
    use std::io::{Error, ErrorKind};

    #[test]
    fn test_error_display() {
        assert_eq!(
            format!(
                "{}",
                MaxMindDbError::InvalidDatabase("something went wrong".to_owned())
            ),
            "Invalid database: something went wrong".to_owned(),
        );
        let io_err = Error::new(ErrorKind::NotFound, "file not found");
        assert_eq!(
            format!("{}", MaxMindDbError::from(io_err)),
            "I/O error: file not found".to_owned(),
        );

        #[cfg(feature = "mmap")]
        {
            let mmap_io_err = Error::new(ErrorKind::PermissionDenied, "mmap failed");
            assert_eq!(
                format!("{}", MaxMindDbError::Mmap(mmap_io_err)),
                "Memory map error: mmap failed".to_owned(),
            );
        }

        assert_eq!(
            format!("{}", MaxMindDbError::Decoding("unexpected type".to_owned())),
            "Decoding error: unexpected type".to_owned(),
        );

        let net_err = IpNetworkError::InvalidPrefix;
        assert_eq!(
            format!("{}", MaxMindDbError::from(net_err)),
            "Invalid network: invalid prefix".to_owned(),
        );
    }

    #[test]
    fn test_lookup_network() {
        use super::Reader;
        use std::collections::HashMap;
        use std::net::IpAddr;

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
                result.found(),
                test.expected_found,
                "IP {} in {}: expected found={}, got found={}",
                test.ip,
                test.db_file,
                test.expected_found,
                result.found()
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
        use super::Reader;
        use crate::geoip2;
        use std::net::IpAddr;

        let reader = Reader::open_readfile("test-data/test-data/GeoIP2-City-Test.mmdb").unwrap();
        let ip: IpAddr = "89.160.20.128".parse().unwrap();

        let result = reader.lookup(ip).unwrap();
        assert!(result.found(), "lookup should find known IP");

        // Decode the data
        let city: geoip2::City = result.decode().unwrap();
        assert!(city.city.is_some(), "Expected city data");

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
    fn test_decode_path() {
        use super::{PathElement, Reader};
        use std::net::IpAddr;

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
    fn test_ipv6_in_ipv4_database() {
        use super::{MaxMindDbError, Reader};
        use std::net::IpAddr;

        let reader =
            Reader::open_readfile("test-data/test-data/MaxMind-DB-test-ipv4-24.mmdb").unwrap();
        let ip: IpAddr = "2001::".parse().unwrap();

        let result = reader.lookup(ip);
        match result {
            Err(MaxMindDbError::InvalidDatabase(msg)) => {
                assert!(
                    msg.contains("IPv6") && msg.contains("IPv4"),
                    "Expected error message about IPv6 in IPv4 database, got: {}",
                    msg
                );
            }
            Err(e) => panic!(
                "Expected InvalidDatabase error for IPv6 in IPv4 database, got: {:?}",
                e
            ),
            Ok(_) => panic!("Expected error for IPv6 lookup in IPv4-only database"),
        }
    }

    #[test]
    fn test_decode_path_comprehensive() {
        use super::{PathElement, Reader};
        use std::net::IpAddr;

        let reader =
            Reader::open_readfile("test-data/test-data/MaxMind-DB-test-decoder.mmdb").unwrap();
        let ip: IpAddr = "::1.1.1.0".parse().unwrap();

        let result = reader.lookup(ip).unwrap();
        assert!(result.found());

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

        // Test negative index: -1 means last element
        let arr_neg1: Option<u32> = result
            .decode_path(&[PathElement::Key("array"), PathElement::Index(-1)])
            .unwrap();
        assert_eq!(arr_neg1, Some(3));

        // Test negative index: -3 means first element
        let arr_neg3: Option<u32> = result
            .decode_path(&[PathElement::Key("array"), PathElement::Index(-3)])
            .unwrap();
        assert_eq!(arr_neg3, Some(1));

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
