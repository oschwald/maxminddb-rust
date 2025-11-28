//! MaxMind DB reader implementation.

use std::collections::HashSet;
use std::fs;
use std::net::IpAddr;
use std::path::Path;

use ipnetwork::IpNetwork;
use serde::Deserialize;

#[cfg(feature = "mmap")]
pub use memmap2::Mmap;
#[cfg(feature = "mmap")]
use memmap2::MmapOptions;
#[cfg(feature = "mmap")]
use std::fs::File;

use crate::decoder;
use crate::error::MaxMindDbError;
use crate::metadata::Metadata;
use crate::result::LookupResult;
use crate::within::{IpInt, Within, WithinNode, WithinOptions};

/// Size of the data section separator (16 zero bytes).
const DATA_SECTION_SEPARATOR_SIZE: usize = 16;

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
    pub(crate) buf: S,
    /// Database metadata.
    pub metadata: Metadata,
    pub(crate) ipv4_start: usize,
    /// Bit depth at which ipv4_start was found (0-96). Used to calculate
    /// correct prefix lengths for IPv4 lookups in IPv6 databases.
    pub(crate) ipv4_start_bit_depth: usize,
    pub(crate) pointer_base: usize,
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
    /// - Check if data exists with [`has_data()`](LookupResult::has_data)
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
    /// if let Some(city) = result.decode::<geoip2::City>()? {
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
            return Err(MaxMindDbError::invalid_input(
                "cannot look up IPv6 address in IPv4-only database",
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

    /// Iterate over all networks in the database.
    ///
    /// This is a convenience method equivalent to calling [`within()`](Self::within)
    /// with `0.0.0.0/0` for IPv4-only databases or `::/0` for IPv6 databases.
    ///
    /// # Arguments
    ///
    /// * `options` - Controls which networks are yielded. Use [`Default::default()`]
    ///   for standard behavior.
    ///
    /// # Examples
    ///
    /// Iterate over all networks with default options:
    /// ```
    /// use maxminddb::{geoip2, Reader};
    ///
    /// let reader = Reader::open_readfile(
    ///     "test-data/test-data/GeoIP2-City-Test.mmdb").unwrap();
    ///
    /// let mut count = 0;
    /// for result in reader.networks(Default::default()).unwrap() {
    ///     let lookup = result.unwrap();
    ///     count += 1;
    ///     if count >= 10 { break; }
    /// }
    /// ```
    pub fn networks(&'de self, options: WithinOptions) -> Result<Within<'de, S>, MaxMindDbError> {
        let cidr = if self.metadata.ip_version == 6 {
            IpNetwork::V6("::/0".parse().unwrap())
        } else {
            IpNetwork::V4("0.0.0.0/0".parse().unwrap())
        };
        self.within(cidr, options)
    }

    /// Iterate over IP networks within a CIDR range.
    ///
    /// Returns an iterator that yields [`LookupResult`] for each network in the
    /// database that falls within the specified CIDR range.
    ///
    /// # Arguments
    ///
    /// * `cidr` - The CIDR range to iterate over.
    /// * `options` - Controls which networks are yielded. Use [`Default::default()`]
    ///   for standard behavior (skip aliases, skip networks without data, include
    ///   empty values).
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
    /// for result in reader.within(ipv4_all, Default::default()).unwrap() {
    ///     let lookup = result.unwrap();
    ///     let network = lookup.network().unwrap();
    ///     let city: geoip2::City = lookup.decode().unwrap().unwrap();
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
    /// for result in reader.within(subnet, Default::default()).unwrap() {
    ///     match result {
    ///         Ok(lookup) => {
    ///             let network = lookup.network().unwrap();
    ///             println!("Found: {}", network);
    ///         }
    ///         Err(e) => eprintln!("Error: {}", e),
    ///     }
    /// }
    /// ```
    ///
    /// Include networks without data:
    /// ```
    /// use ipnetwork::IpNetwork;
    /// use maxminddb::{Reader, WithinOptions};
    ///
    /// let reader = Reader::open_readfile(
    ///     "test-data/test-data/MaxMind-DB-test-mixed-24.mmdb").unwrap();
    ///
    /// let opts = WithinOptions::default().include_networks_without_data();
    /// for result in reader.within("1.0.0.0/8".parse().unwrap(), opts).unwrap() {
    ///     let lookup = result.unwrap();
    ///     if !lookup.has_data() {
    ///         println!("Network {} has no data", lookup.network().unwrap());
    ///     }
    /// }
    /// ```
    pub fn within(
        &'de self,
        cidr: IpNetwork,
        options: WithinOptions,
    ) -> Result<Within<'de, S>, MaxMindDbError> {
        let ip_address = cidr.network();
        let prefix_len = cidr.prefix() as usize;
        let ip_int = IpInt::new(ip_address);
        let bit_count = ip_int.bit_count();

        let mut node = self.start_node(bit_count);
        let node_count = self.metadata.node_count as usize;

        let mut stack: Vec<WithinNode> = Vec::with_capacity(bit_count - prefix_len);

        // Traverse down the tree to the level that matches the cidr mark
        let mut depth = 0_usize;
        for i in 0..prefix_len {
            let bit = ip_int.get_bit(i);
            node = self.read_node(node, bit as usize)?;
            depth = i + 1; // We've now traversed i+1 bits (bits 0 through i)

            if node >= node_count {
                // We've hit a data node or dead end before we exhausted our prefix.
                // This means the requested CIDR is contained in a single record.
                break;
            }
        }

        // Always push the node - it could be:
        // - A data node (> node_count): will be yielded as a single record
        // - The empty node (== node_count): will be skipped unless include_networks_without_data
        // - An internal node (< node_count): will be traversed to find all contained records
        stack.push(WithinNode {
            node,
            ip_int,
            prefix_len: depth,
        });

        let within = Within {
            reader: self,
            node_count,
            stack,
            options,
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
            _ if node == node_count => Ok((0, prefix_len)),
            _ if node > node_count => Ok((node, prefix_len)),
            _ => Err(MaxMindDbError::invalid_database(
                "invalid node in search tree",
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
        let mut node: usize = 0;
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
    pub(crate) fn read_node(
        &self,
        node_number: usize,
        index: usize,
    ) -> Result<usize, MaxMindDbError> {
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
                return Err(MaxMindDbError::invalid_database(format!(
                    "unknown record size: {s}"
                )))
            }
        };
        Ok(val)
    }

    /// Resolves a pointer from the search tree to an offset in the data section.
    #[inline]
    pub(crate) fn resolve_data_pointer(&self, pointer: usize) -> Result<usize, MaxMindDbError> {
        let resolved = pointer - (self.metadata.node_count as usize) - 16;

        // Check bounds using pointer_base which marks the start of the data section
        if resolved >= (self.buf.as_ref().len() - self.pointer_base) {
            return Err(MaxMindDbError::invalid_database(
                "the MaxMind DB file's data pointer resolves to an invalid location",
            ));
        }

        Ok(resolved)
    }

    /// Performs comprehensive validation of the MaxMind DB file.
    ///
    /// This method validates:
    /// - Metadata section: format versions, required fields, and value constraints
    /// - Search tree: traverses all networks to verify tree structure integrity
    /// - Data section separator: validates the 16-byte separator between tree and data
    /// - Data section: verifies all data records referenced by the search tree
    ///
    /// The verifier is stricter than the MaxMind DB specification and may return
    /// errors on some databases that are still readable by normal operations.
    /// This method is useful for:
    /// - Validating database files after download or generation
    /// - Debugging database corruption issues
    /// - Ensuring database integrity in critical applications
    ///
    /// Note: Verification traverses the entire database and may be slow on large files.
    /// The method is thread-safe and can be called on an active Reader.
    ///
    /// # Example
    ///
    /// ```
    /// use maxminddb::Reader;
    ///
    /// let reader = Reader::open_readfile("test-data/test-data/GeoIP2-City-Test.mmdb").unwrap();
    /// reader.verify().expect("Database should be valid");
    /// ```
    pub fn verify(&self) -> Result<(), MaxMindDbError> {
        self.verify_metadata()?;
        self.verify_database()
    }

    fn verify_metadata(&self) -> Result<(), MaxMindDbError> {
        let m = &self.metadata;

        if m.binary_format_major_version != 2 {
            return Err(MaxMindDbError::invalid_database(format!(
                "binary_format_major_version - Expected: 2 Actual: {}",
                m.binary_format_major_version
            )));
        }
        if m.binary_format_minor_version != 0 {
            return Err(MaxMindDbError::invalid_database(format!(
                "binary_format_minor_version - Expected: 0 Actual: {}",
                m.binary_format_minor_version
            )));
        }
        if m.database_type.is_empty() {
            return Err(MaxMindDbError::invalid_database(
                "database_type - Expected: non-empty string Actual: \"\"",
            ));
        }
        if m.description.is_empty() {
            return Err(MaxMindDbError::invalid_database(
                "description - Expected: non-empty map Actual: {}",
            ));
        }
        if m.ip_version != 4 && m.ip_version != 6 {
            return Err(MaxMindDbError::invalid_database(format!(
                "ip_version - Expected: 4 or 6 Actual: {}",
                m.ip_version
            )));
        }
        if m.record_size != 24 && m.record_size != 28 && m.record_size != 32 {
            return Err(MaxMindDbError::invalid_database(format!(
                "record_size - Expected: 24, 28, or 32 Actual: {}",
                m.record_size
            )));
        }
        if m.node_count == 0 {
            return Err(MaxMindDbError::invalid_database(
                "node_count - Expected: positive integer Actual: 0",
            ));
        }
        Ok(())
    }

    fn verify_database(&self) -> Result<(), MaxMindDbError> {
        let offsets = self.verify_search_tree()?;
        self.verify_data_section_separator()?;
        self.verify_data_section(offsets)
    }

    fn verify_search_tree(&self) -> Result<HashSet<usize>, MaxMindDbError> {
        let mut offsets = HashSet::new();
        let opts = WithinOptions::default().include_networks_without_data();

        // Maximum number of networks we can expect in a valid database.
        // A database with N nodes can have at most 2N data entries (each leaf node
        // can have data). We add some margin for safety.
        let max_iterations = (self.metadata.node_count as usize).saturating_mul(3);
        let mut iteration_count = 0usize;

        for result in self.networks(opts)? {
            let lookup = result?;
            if let Some(offset) = lookup.offset() {
                offsets.insert(offset);
            }

            iteration_count += 1;
            if iteration_count > max_iterations {
                return Err(MaxMindDbError::invalid_database(format!(
                    "search tree appears to have a cycle or invalid structure (exceeded {max_iterations} iterations)"
                )));
            }
        }
        Ok(offsets)
    }

    fn verify_data_section_separator(&self) -> Result<(), MaxMindDbError> {
        let separator_start =
            self.metadata.node_count as usize * self.metadata.record_size as usize / 4;
        let separator_end = separator_start + DATA_SECTION_SEPARATOR_SIZE;

        if separator_end > self.buf.as_ref().len() {
            return Err(MaxMindDbError::invalid_database_at(
                "data section separator extends past end of file",
                separator_start,
            ));
        }

        let separator = &self.buf.as_ref()[separator_start..separator_end];

        for &b in separator {
            if b != 0 {
                return Err(MaxMindDbError::invalid_database_at(
                    format!("unexpected byte in data separator: {separator:?}"),
                    separator_start,
                ));
            }
        }
        Ok(())
    }

    fn verify_data_section(&self, offsets: HashSet<usize>) -> Result<(), MaxMindDbError> {
        let data_section = &self.buf.as_ref()[self.pointer_base..];

        // Verify each offset from the search tree points to valid, decodable data
        for &offset in &offsets {
            if offset >= data_section.len() {
                return Err(MaxMindDbError::invalid_database_at(
                    format!(
                        "search tree pointer is beyond data section (len: {})",
                        data_section.len()
                    ),
                    offset,
                ));
            }

            let mut dec = decoder::Decoder::new(data_section, offset);

            // Try to skip/decode the value to verify it's valid
            if let Err(e) = dec.skip_value_for_verification() {
                return Err(MaxMindDbError::invalid_database_at(
                    format!("decoding error: {e}"),
                    offset,
                ));
            }
        }

        Ok(())
    }
}

fn find_metadata_start(buf: &[u8]) -> Result<usize, MaxMindDbError> {
    const METADATA_START_MARKER: &[u8] = b"\xab\xcd\xefMaxMind.com";

    memchr::memmem::rfind(buf, METADATA_START_MARKER)
        .map(|x| x + METADATA_START_MARKER.len())
        .ok_or_else(|| {
            MaxMindDbError::invalid_database("could not find MaxMind DB metadata in file")
        })
}
