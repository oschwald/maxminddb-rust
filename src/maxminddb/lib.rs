#![deny(trivial_casts, trivial_numeric_casts, unused_import_braces)]

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt::Display;
use std::fs;
use std::io;
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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

#[derive(Debug)]
pub struct Within<'de, T: Deserialize<'de>, S: AsRef<[u8]>> {
    reader: &'de Reader<S>,
    node_count: usize,
    stack: Vec<WithinNode>,
    phantom: PhantomData<&'de T>,
}

#[derive(Debug)]
pub struct WithinItem<T> {
    pub ip_net: IpNetwork,
    pub info: T,
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

impl<'de, T: Deserialize<'de>, S: AsRef<[u8]>> Iterator for Within<'de, T, S> {
    type Item = Result<WithinItem<T>, MaxMindDbError>;

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
                    let ip_net =
                        match bytes_and_prefix_to_net(&current.ip_int, current.prefix_len as u8) {
                            Ok(ip_net) => ip_net,
                            Err(e) => return Some(Err(e)),
                        };

                    // Call the new helper method to decode data
                    return match self.reader.decode_data_at_pointer(current.node) {
                        Ok(info) => Some(Ok(WithinItem { ip_net, info })),
                        Err(e) => Some(Err(e)),
                    };
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

/// A reader for the MaxMind DB format. The lifetime `'data` is tied to the lifetime of the underlying buffer holding the contents of the database file.
#[derive(Debug)]
pub struct Reader<S: AsRef<[u8]>> {
    buf: S,
    pub metadata: Metadata,
    ipv4_start: usize,
    pointer_base: usize,
}

#[cfg(feature = "mmap")]
impl<'de> Reader<Mmap> {
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
    /// let reader = maxminddb::Reader::open_readfile("test-data/test-data/GeoIP2-City-Test.mmdb").unwrap();
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
        };
        reader.ipv4_start = reader.find_ipv4_start()?;

        Ok(reader)
    }

    /// Lookup the socket address in the opened MaxMind DB.
    /// Returns `Ok(None)` if the address is not found in the database.
    ///
    /// Example:
    ///
    /// ```
    /// # use maxminddb::geoip2;
    /// # use std::net::IpAddr;
    /// # use std::str::FromStr;
    /// # fn main() -> Result<(), maxminddb::MaxMindDbError> {
    /// let reader = maxminddb::Reader::open_readfile("test-data/test-data/GeoIP2-City-Test.mmdb")?;
    ///
    /// let ip: IpAddr = FromStr::from_str("89.160.20.128").unwrap();
    /// if let Some(city) = reader.lookup::<geoip2::City>(ip)? {
    ///     println!("{:?}", city);
    /// } else {
    ///     println!("Address not found");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn lookup<T>(&'de self, address: IpAddr) -> Result<Option<T>, MaxMindDbError>
    where
        T: Deserialize<'de>,
    {
        self.lookup_prefix(address)
            .map(|(option_value, _prefix_len)| option_value)
    }

    /// Lookup the socket address in the opened MaxMind DB, returning the found value (if any)
    /// and the prefix length of the network associated with the lookup.
    ///
    /// Returns `Ok((None, prefix_len))` if the address is found in the tree but has no data record.
    /// Returns `Err(...)` for database errors (IO, corruption, decoding).
    ///
    /// Example:
    ///
    /// ```
    /// # use maxminddb::geoip2;
    /// # use std::net::IpAddr;
    /// # use std::str::FromStr;
    /// # fn main() -> Result<(), maxminddb::MaxMindDbError> {
    /// let reader = maxminddb::Reader::open_readfile("test-data/test-data/GeoIP2-City-Test.mmdb")?;
    ///
    /// let ip: IpAddr = "89.160.20.128".parse().unwrap(); // Known IP
    /// let ip_unknown: IpAddr = "10.0.0.1".parse().unwrap(); // Unknown IP
    ///
    /// let (city_option, prefix_len) = reader.lookup_prefix::<geoip2::City>(ip)?;
    /// if let Some(city) = city_option {
    ///     println!("Found {:?} at prefix length {}", city.city.unwrap().names.unwrap().get("en").unwrap(), prefix_len);
    /// } else {
    ///     // This case is less likely with lookup_prefix if the IP resolves in the tree
    ///     println!("IP found in tree but no data (prefix_len: {})", prefix_len);
    /// }
    ///
    /// let (city_option_unknown, prefix_len_unknown) = reader.lookup_prefix::<geoip2::City>(ip_unknown)?;
    /// assert!(city_option_unknown.is_none());
    /// println!("Unknown IP resolved to prefix_len: {}", prefix_len_unknown);
    /// # Ok(())
    /// # }
    /// ```
    pub fn lookup_prefix<T>(
        &'de self,
        address: IpAddr,
    ) -> Result<(Option<T>, usize), MaxMindDbError>
    where
        T: Deserialize<'de>,
    {
        let ip_int = IpInt::new(address);
        // find_address_in_tree returns Result<(usize, usize), MaxMindDbError> -> (pointer, prefix_len)
        let (pointer, prefix_len) = self.find_address_in_tree(&ip_int)?;

        if pointer == 0 {
            // If pointer is 0, it signifies no data record was associated during tree traversal.
            // Return None for the data, but include the calculated prefix_len.
            return Ok((None, prefix_len));
        }

        // If pointer > 0, attempt to resolve and decode data using the helper method
        match self.decode_data_at_pointer(pointer) {
            Ok(value) => Ok((Some(value), prefix_len)),
            Err(e) => Err(e),
        }
    }

    /// Iterate over blocks of IP networks in the opened MaxMind DB
    ///
    /// Example:
    ///
    /// ```
    /// use ipnetwork::IpNetwork;
    /// use maxminddb::{geoip2, Within};
    ///
    /// let reader = maxminddb::Reader::open_readfile("test-data/test-data/GeoIP2-City-Test.mmdb").unwrap();
    ///
    /// let ip_net = IpNetwork::V6("::/0".parse().unwrap());
    /// let mut iter: Within<geoip2::City, _> = reader.within(ip_net).unwrap();
    /// while let Some(next) = iter.next() {
    ///     let item = next.unwrap();
    ///     println!("ip_net={}, city={:?}", item.ip_net, item.info);
    /// }
    /// ```
    pub fn within<T>(&'de self, cidr: IpNetwork) -> Result<Within<'de, T, S>, MaxMindDbError>
    where
        T: Deserialize<'de>,
    {
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

        let within: Within<T, S> = Within {
            reader: self,
            node_count,
            stack,
            phantom: PhantomData,
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

    fn start_node(&self, length: usize) -> usize {
        if length == 128 {
            0
        } else {
            self.ipv4_start
        }
    }

    fn find_ipv4_start(&self) -> Result<usize, MaxMindDbError> {
        if self.metadata.ip_version != 6 {
            return Ok(0);
        }

        // We are looking up an IPv4 address in an IPv6 tree. Skip over the
        // first 96 nodes.
        let mut node: usize = 0_usize;
        for _ in 0_u8..96 {
            if node >= self.metadata.node_count as usize {
                break;
            }
            node = self.read_node(node, 0)?;
        }
        Ok(node)
    }

    fn read_node(&self, node_number: usize, index: usize) -> Result<usize, MaxMindDbError> {
        let buf = self.buf.as_ref();
        let base_offset = node_number * (self.metadata.record_size as usize) / 4;

        let val = match self.metadata.record_size {
            24 => {
                let offset = base_offset + index * 3;
                to_usize(0, &buf[offset..offset + 3])
            }
            28 => {
                let mut middle = buf[base_offset + 3];
                if index != 0 {
                    middle &= 0x0F
                } else {
                    middle = (0xF0 & middle) >> 4
                }
                let offset = base_offset + index * 4;
                to_usize(middle, &buf[offset..offset + 3])
            }
            32 => {
                let offset = base_offset + index * 4;
                to_usize(0, &buf[offset..offset + 4])
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

    /// Decodes data at the given pointer offset.
    /// Assumes the pointer is valid and points to the data section.
    fn decode_data_at_pointer<T>(&'de self, pointer: usize) -> Result<T, MaxMindDbError>
    where
        T: Deserialize<'de>,
    {
        let resolved_offset = self.resolve_data_pointer(pointer)?;
        let mut decoder =
            decoder::Decoder::new(&self.buf.as_ref()[self.pointer_base..], resolved_offset);
        T::deserialize(&mut decoder)
    }
}

// I haven't moved all patterns of this form to a generic function as
// the FromPrimitive trait is unstable
fn to_usize(base: u8, bytes: &[u8]) -> usize {
    bytes
        .iter()
        .fold(base as usize, |acc, &b| (acc << 8) | b as usize)
}

#[inline]
fn bytes_and_prefix_to_net(bytes: &IpInt, prefix: u8) -> Result<IpNetwork, MaxMindDbError> {
    let (ip, prefix) = match bytes {
        IpInt::V4(ip) => (IpAddr::V4(Ipv4Addr::from(*ip)), prefix),
        IpInt::V6(ip) if bytes.is_ipv4_in_ipv6() => {
            (IpAddr::V4(Ipv4Addr::from(*ip as u32)), prefix - 96)
        }
        IpInt::V6(ip) => (IpAddr::V6(Ipv6Addr::from(*ip)), prefix),
    };
    IpNetwork::new(ip, prefix).map_err(MaxMindDbError::InvalidNetwork)
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
    fn test_lookup_returns_none_for_unknown_address() {
        use super::Reader;
        use crate::geoip2;
        use std::net::IpAddr;
        use std::str::FromStr;

        let reader = Reader::open_readfile("test-data/test-data/GeoIP2-City-Test.mmdb").unwrap();
        let ip: IpAddr = FromStr::from_str("10.0.0.1").unwrap();

        let result_lookup = reader.lookup::<geoip2::City>(ip);
        assert!(
            matches!(result_lookup, Ok(None)),
            "lookup should return Ok(None) for unknown IP"
        );

        let result_lookup_prefix = reader.lookup_prefix::<geoip2::City>(ip);
        assert!(
            matches!(result_lookup_prefix, Ok((None, 8))),
            "lookup_prefix should return Ok((None, 8)) for unknown IP, got {:?}",
            result_lookup_prefix
        );
    }

    #[test]
    fn test_lookup_returns_some_for_known_address() {
        use super::Reader;
        use crate::geoip2;
        use std::net::IpAddr;
        use std::str::FromStr;

        let reader = Reader::open_readfile("test-data/test-data/GeoIP2-City-Test.mmdb").unwrap();
        let ip: IpAddr = FromStr::from_str("89.160.20.128").unwrap();

        let result_lookup = reader.lookup::<geoip2::City>(ip);
        assert!(
            matches!(result_lookup, Ok(Some(_))),
            "lookup should return Ok(Some(_)) for known IP"
        );
        assert!(
            result_lookup.unwrap().unwrap().city.is_some(),
            "Expected city data"
        );

        let result_lookup_prefix = reader.lookup_prefix::<geoip2::City>(ip);
        assert!(
            matches!(result_lookup_prefix, Ok((Some(_), _))),
            "lookup_prefix should return Ok(Some(_)) for known IP"
        );
        let (city_data, prefix_len) = result_lookup_prefix.unwrap();
        assert!(
            city_data.unwrap().city.is_some(),
            "Expected city data from prefix lookup"
        );
        assert_eq!(prefix_len, 25, "Expected valid prefix length");
    }
}
