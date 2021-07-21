
use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use ipnetwork::IpNetwork;
use serde::{de, Deserialize};

#[cfg(feature = "mmap")]
pub use memmap2::Mmap;
#[cfg(feature = "mmap")]
use memmap2::MmapOptions;
#[cfg(feature = "mmap")]
use std::fs::File;

#[derive(Debug, PartialEq)]
pub enum MaxMindDBError {
    AddressNotFoundError(String),
    InvalidDatabaseError(String),
    IoError(String),
    MapError(String),
    DecodingError(String),
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
            MaxMindDBError::AddressNotFoundError(msg) => {
                write!(fmt, "AddressNotFoundError: {}", msg)?
            }
            MaxMindDBError::InvalidDatabaseError(msg) => {
                write!(fmt, "InvalidDatabaseError: {}", msg)?
            }
            MaxMindDBError::IoError(msg) => write!(fmt, "IoError: {}", msg)?,
            MaxMindDBError::MapError(msg) => write!(fmt, "MapError: {}", msg)?,
            MaxMindDBError::DecodingError(msg) => write!(fmt, "DecodingError: {}", msg)?,
        }
        Ok(())
    }
}

// Use default implementation for `std::error::Error`
impl std::error::Error for MaxMindDBError {}

impl de::Error for MaxMindDBError {
    fn custom<T: Display>(msg: T) -> Self {
        MaxMindDBError::DecodingError(format!("{}", msg))
    }
}

#[derive(Deserialize, Debug)]
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
    /// let reader = maxminddb::Reader::open_mmap("test-data/test-data/GeoIP2-City-Test.mmdb").unwrap();
    /// ```
    pub fn open_mmap<P: AsRef<Path>>(database: P) -> Result<Reader<Mmap>, MaxMindDBError> {
        let file_read = File::open(database)?;
        let mmap = unsafe { MmapOptions::new().map(&file_read) }?;
        Reader::from_source(mmap)
    }
}

impl<'de> Reader<Vec<u8>> {
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

#[derive(Debug)]
struct WithinNode {
    node: usize,
    ip_bytes: Vec<u8>,
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
    pub info: T
}

impl<'de, T: Deserialize<'de>, S: AsRef<[u8]>> Iterator for Within<'de, T, S> {
    type Item = WithinItem<T>;

    fn next(&mut self) -> Option<Self::Item> {

        while !self.stack.is_empty() {
            let current = self.stack.pop().unwrap();
//            println!("    current={:#?}", current);
            let bit_count = current.ip_bytes.len() * 8;

            if current.node > self.node_count {
                // This is a data node, emit it and we're done (until the following next call)
                let ip_net = bytes_and_prefix_to_net(&current.ip_bytes, current.prefix_len as u8);
//                println!("      emit: current={:#?}, net={}", current, net);
                // TODO: error handling (should this be a method?)
                let rec = self.reader.resolve_data_pointer(current.node).unwrap();
                let mut decoder = decoder::Decoder::new(&self.reader.buf.as_ref()[self.reader.pointer_base..], rec);
                return Some(WithinItem {
                    ip_net,
                    info: T::deserialize(&mut decoder).unwrap(),
                })
            } else if current.node == self.node_count {
                // Dead end, nothing to do
            } else {
                // In order traversal of our children
                // right/1-bit
                let mut right_ip_bytes = current.ip_bytes.clone();
                right_ip_bytes[current.prefix_len >> 3] |= 1 << ((bit_count - current.prefix_len - 1) % 8);
                self.stack.push(WithinNode {
                    // TODO: error handling
                    node: self.reader.read_node(current.node, 1).unwrap(),
                    ip_bytes: right_ip_bytes,
                    prefix_len: current.prefix_len + 1,
                });
                // left/0-bit
                self.stack.push(WithinNode {
                    // TODO: error handling
                    node: self.reader.read_node(current.node, 0).unwrap(),
                    ip_bytes: current.ip_bytes.clone(),
                    prefix_len: current.prefix_len + 1,
                });
            }
        }
        None
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

    /// Lookup the socket address in the opened MaxMind DB
    ///
    /// Example:
    ///
    /// ```
    /// use maxminddb::geoip2;
    /// use std::net::IpAddr;
    /// use std::str::FromStr;
    ///
    /// let reader = maxminddb::Reader::open_readfile("test-data/test-data/GeoIP2-City-Test.mmdb").unwrap();
    ///
    /// let ip: IpAddr = FromStr::from_str("89.160.20.128").unwrap();
    /// let city: geoip2::City = reader.lookup(ip).unwrap();
    /// print!("{:?}", city);
    /// ```
    pub fn lookup<T>(&'de self, address: IpAddr) -> Result<T, MaxMindDBError>
    where
        T: Deserialize<'de>,
    {
        let ip_bytes = ip_to_bytes(address);
        let pointer = self.find_address_in_tree(&ip_bytes)?;
        if pointer == 0 {
            return Err(MaxMindDBError::AddressNotFoundError(
                "Address not found in database".to_owned(),
            ));
        }
        let rec = self.resolve_data_pointer(pointer)?;
        let mut decoder = decoder::Decoder::new(&self.buf.as_ref()[self.pointer_base..], rec);

        T::deserialize(&mut decoder)
    }

    pub fn within<T>(&'de self, cidr: IpNetwork) -> Result<Within<T, S>, MaxMindDBError>
    where
        T: Deserialize<'de>,
    {
//        println!("within: cidr={}", cidr);
        let ip_address = cidr.network();
//        println!("  ip_address={}", ip_address);
        let prefix_len =cidr.prefix() as usize;
//        println!("  prefix={}", prefix_len);
        let ip_bytes = ip_to_bytes(ip_address);
//        println!("  ip_bytes={:#?}", ip_bytes);
        let bit_count = ip_bytes.len() * 8;
//        println!("  bit_count={:#?}", bit_count);

        let mut node = self.start_node(bit_count);
//        println!("  node={}", node);
        let node_count = self.metadata.node_count as usize;
//        println!("  node_count={}", node_count);

        let mut stack: Vec<WithinNode> = Vec::with_capacity(bit_count - prefix_len);

        // Traverse down the tree to the level that matches the cidr mark
        let mut i = 0_usize;
        while i < prefix_len {
//            println!("  i={}", i);
            let bit = 1 & (ip_bytes[i >> 3] >> 7 - (i % 8)) as usize;
//            println!("    bit={}", bit);
            // TODO: error handling
            node = self.read_node(node, bit).unwrap();
//            println!("    node={}", node);
            if node >= node_count {
                // We've hit a dead end before we exhausted our prefix
                break
            }

            i += 1;
        }

        if node < node_count {
            // Ok, now anything that's below node in the tree is "within", start with the node we
            // traversed to as our to be processed stack.
            stack.push(WithinNode { node, ip_bytes, prefix_len });
        }
        // else the stack will be empty and we'll be returning an iterator that visits nothing,
        // which makes sense.

//        println!("  stack={:#?}", stack);
        let within: Within<T, S> = Within {
            reader: self,
            node_count,
            stack,
            phantom: PhantomData,
        };

        Ok(within)
    }

    fn find_address_in_tree(&self, ip_address: &[u8]) -> Result<usize, MaxMindDBError> {
        let bit_count = ip_address.len() * 8;
        let mut node = self.start_node(bit_count);

        let node_count = self.metadata.node_count as usize;

        for i in 0..bit_count {
            if node >= node_count {
                break;
            }
            let bit = 1 & (ip_address[i >> 3] >> (7 - (i % 8)));

            node = self.read_node(node, bit as usize)?;
        }
        match node_count {
            n if n == node => Ok(0),
            n if node > n => Ok(node),
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
                     {:?}",
                    s
                )))
            }
        };
        Ok(val)
    }

    fn resolve_data_pointer(&self, pointer: usize) -> Result<usize, MaxMindDBError> {
        let resolved = pointer - (self.metadata.node_count as usize) - 16;

        if resolved > self.buf.as_ref().len() {
            return Err(MaxMindDBError::InvalidDatabaseError(
                "the MaxMind DB file's search tree \
                 is corrupt"
                    .to_owned(),
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

fn ip_to_bytes(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    }
}

fn bytes_and_prefix_to_net(bytes: &Vec<u8>, prefix: u8) -> IpNetwork {
    let ip = match bytes.len() {
        4 => IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])),
        16 => {
            let a = (bytes[0] as u16) << 8 | bytes[1] as u16;
            let b = (bytes[2] as u16) << 8 | bytes[3] as u16;
            let c = (bytes[4] as u16) << 8 | bytes[5] as u16;
            let d = (bytes[6] as u16) << 8 | bytes[7] as u16;
            let e = (bytes[8] as u16) << 8 | bytes[9] as u16;
            let f = (bytes[10] as u16) << 8 | bytes[11] as u16;
            let g = (bytes[12] as u16) << 8 | bytes[13] as u16;
            let h = (bytes[14] as u16) << 8 | bytes[15] as u16;
            IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h))
        },
        // TODO: error handling
        _ => IpAddr::V4(Ipv4Addr::new(0x00, 0x00, 0x00, 0x00)),
    };
    // TODO: Error handling
    IpNetwork::new(ip, prefix).unwrap()
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
                MaxMindDBError::AddressNotFoundError("something went wrong".to_owned())
            ),
            "AddressNotFoundError: something went wrong".to_owned(),
        );
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
    }
}
