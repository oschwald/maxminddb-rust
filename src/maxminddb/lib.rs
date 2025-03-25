#![deny(trivial_casts, trivial_numeric_casts, unused_import_braces)]

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use ipnetwork::IpNetwork;
use serde::{de, Deserialize, Serialize};

#[cfg(feature = "mmap")]
pub use memmap2::Mmap;
#[cfg(feature = "mmap")]
use memmap2::MmapOptions;
#[cfg(feature = "mmap")]
use std::fs::File;

#[cfg(all(feature = "simdutf8", feature = "unsafe-str-decode"))]
compile_error!("features `simdutf8` and `unsafe-str-decode` are mutually exclusive");

#[derive(Debug, PartialEq, Eq)]
pub enum MaxMindDBError {
    InvalidDatabaseError(String),
    IoError(String),
    MapError(String),
    DecodingError(String),
    InvalidNetworkError(String),
}

impl From<io::Error> for MaxMindDBError {
    fn from(err: io::Error) -> MaxMindDBError {
        // clean up and clean up MaxMindDBError generally
        MaxMindDBError::IoError(err.to_string())
    }
}

impl Display for MaxMindDBError {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            MaxMindDBError::InvalidDatabaseError(msg) => {
                write!(fmt, "InvalidDatabaseError: {msg}")?
            }
            MaxMindDBError::IoError(msg) => write!(fmt, "IoError: {msg}")?,
            MaxMindDBError::MapError(msg) => write!(fmt, "MapError: {msg}")?,
            MaxMindDBError::DecodingError(msg) => write!(fmt, "DecodingError: {msg}")?,
            MaxMindDBError::InvalidNetworkError(msg) => write!(fmt, "InvalidNetworkError: {msg}")?,
        }
        Ok(())
    }
}

// Use default implementation for `std::error::Error`
impl std::error::Error for MaxMindDBError {}

impl de::Error for MaxMindDBError {
    fn custom<T: Display>(msg: T) -> Self {
        MaxMindDBError::DecodingError(format!("{msg}"))
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
    type Item = Result<WithinItem<T>, MaxMindDBError>;

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
                    // TODO: should this block become a helper method on reader?
                    let rec = match self.reader.resolve_data_pointer(current.node) {
                        Ok(rec) => rec,
                        Err(e) => return Some(Err(e)),
                    };
                    let mut decoder = decoder::Decoder::new(
                        &self.reader.buf.as_ref()[self.reader.pointer_base..],
                        rec,
                    );
                    return match T::deserialize(&mut decoder) {
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
    pub fn open_mmap<P: AsRef<Path>>(database: P) -> Result<Reader<Mmap>, MaxMindDBError> {
        let file_read = File::open(database)?;
        let mmap = unsafe { MmapOptions::new().map(&file_read) }?;
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
    pub fn open_readfile<P: AsRef<Path>>(database: P) -> Result<Reader<Vec<u8>>, MaxMindDBError> {
        use std::fs;

        let buf: Vec<u8> = fs::read(&database)?;
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
    pub fn from_source(buf: S) -> Result<Reader<S>, MaxMindDBError> {
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
    /// # fn main() -> Result<(), maxminddb::MaxMindDBError> {
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
    pub fn lookup<T>(&'de self, address: IpAddr) -> Result<Option<T>, MaxMindDBError>
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
    /// # fn main() -> Result<(), maxminddb::MaxMindDBError> {
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
    ) -> Result<(Option<T>, usize), MaxMindDBError>
    where
        T: Deserialize<'de>,
    {
        let ip_int = IpInt::new(address);
        // find_address_in_tree returns Result<(usize, usize), MaxMindDBError> -> (pointer, prefix_len)
        let (pointer, prefix_len) = self.find_address_in_tree(&ip_int)?;

        if pointer == 0 {
            // If pointer is 0, it signifies no data record was associated during tree traversal.
            // Return None for the data, but include the calculated prefix_len.
            return Ok((None, prefix_len));
        }

        // If pointer > 0, attempt to resolve and decode data
        let rec = self.resolve_data_pointer(pointer)?;
        let mut decoder = decoder::Decoder::new(&self.buf.as_ref()[self.pointer_base..], rec);

        // Attempt to deserialize. If successful, wrap in Some. If error, propagate.
        match T::deserialize(&mut decoder) {
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
    pub fn within<T>(&'de self, cidr: IpNetwork) -> Result<Within<'de, T, S>, MaxMindDBError>
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

    fn find_address_in_tree(&self, ip_int: &IpInt) -> Result<(usize, usize), MaxMindDBError> {
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
            _ => Err(MaxMindDBError::InvalidDatabaseError(
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

    fn find_ipv4_start(&self) -> Result<usize, MaxMindDBError> {
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

    fn read_node(&self, node_number: usize, index: usize) -> Result<usize, MaxMindDBError> {
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
                return Err(MaxMindDBError::InvalidDatabaseError(format!(
                    "unknown record size: \
                     {s:?}"
                )))
            }
        };
        Ok(val)
    }

    fn resolve_data_pointer(&self, pointer: usize) -> Result<usize, MaxMindDBError> {
        let resolved = pointer - (self.metadata.node_count as usize) - 16;

        // Check bounds using pointer_base which marks the start of the data section
        if resolved >= (self.buf.as_ref().len() - self.pointer_base) {
            return Err(MaxMindDBError::InvalidDatabaseError(
                "the MaxMind DB file's data pointer resolves to an invalid location".to_owned(),
            ));
        }

        Ok(resolved)
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
fn bytes_and_prefix_to_net(bytes: &IpInt, prefix: u8) -> Result<IpNetwork, MaxMindDBError> {
    let (ip, prefix) = match bytes {
        IpInt::V4(ip) => (IpAddr::V4(Ipv4Addr::from(*ip)), prefix),
        IpInt::V6(ip) if bytes.is_ipv4_in_ipv6() => {
            (IpAddr::V4(Ipv4Addr::from(*ip as u32)), prefix - 96)
        }
        IpInt::V6(ip) => (IpAddr::V6(Ipv6Addr::from(*ip)), prefix),
    };
    IpNetwork::new(ip, prefix).map_err(|e| MaxMindDBError::InvalidNetworkError(e.to_string()))
}

fn find_metadata_start(buf: &[u8]) -> Result<usize, MaxMindDBError> {
    const METADATA_START_MARKER: &[u8] = b"\xab\xcd\xefMaxMind.com";

    memchr::memmem::rfind(buf, METADATA_START_MARKER)
        .map(|x| x + METADATA_START_MARKER.len())
        .ok_or_else(|| {
            MaxMindDBError::InvalidDatabaseError(
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
    use super::MaxMindDBError;

    #[test]
    fn test_error_display() {
        assert_eq!(
            format!(
                "{}",
                MaxMindDBError::InvalidDatabaseError("something went wrong".to_owned())
            ),
            "InvalidDatabaseError: something went wrong".to_owned(),
        );
        assert_eq!(
            format!(
                "{}",
                MaxMindDBError::IoError("something went wrong".to_owned())
            ),
            "IoError: something went wrong".to_owned(),
        );
        assert_eq!(
            format!(
                "{}",
                MaxMindDBError::MapError("something went wrong".to_owned())
            ),
            "MapError: something went wrong".to_owned(),
        );
        assert_eq!(
            format!(
                "{}",
                MaxMindDBError::DecodingError("something went wrong".to_owned())
            ),
            "DecodingError: something went wrong".to_owned(),
        );
        assert_eq!(
            format!(
                "{}",
                MaxMindDBError::InvalidNetworkError("something went wrong".to_owned())
            ),
            "InvalidNetworkError: something went wrong".to_owned(),
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
            "lookup_prefix should return Ok(None) for unknown IP"
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
