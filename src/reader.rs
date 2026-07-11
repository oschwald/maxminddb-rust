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
use crate::result::{LookupResult, LookupSource, NetworkKind};
use crate::within::{IpInt, Within, WithinNode, WithinOptions};

/// Size of the data section separator (16 zero bytes).
const DATA_SECTION_SEPARATOR_SIZE: usize = 16;
const METADATA_START_MARKER: &[u8] = b"\xab\xcd\xefMaxMind.com";

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
pub struct Reader<S: AsRef<[u8]>> {
    pub(crate) buf: S,
    /// Database metadata.
    metadata: Metadata,
    record_size: u16,
    /// Cached `Metadata::node_count` for `Reader` search-tree traversal.
    /// Use this instead of `metadata.node_count` for traversal invariants.
    node_count: usize,
    /// Cached bytes per node derived from `Metadata::record_size` for `Reader`.
    /// Use this instead of `metadata.record_size` in lookup hot paths.
    node_byte_size: usize,
    pub(crate) ipv4_start: usize,
    /// Bit depth at which ipv4_start was found (0-96). Used to calculate
    /// correct prefix lengths for IPv4 lookups in IPv6 databases.
    pub(crate) ipv4_start_bit_depth: usize,
    pub(crate) pointer_base: usize,
    pub(crate) data_section_len: usize,
    pub(crate) metadata_start: usize,
}

impl<S: AsRef<[u8]>> std::fmt::Debug for Reader<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reader")
            .field("buf_len", &self.buf.as_ref().len())
            .field("metadata", &self.metadata)
            .field("ipv4_start", &self.ipv4_start)
            .field("ipv4_start_bit_depth", &self.ipv4_start_bit_depth)
            .field("pointer_base", &self.pointer_base)
            .field("data_section_len", &self.data_section_len)
            .field("metadata_start", &self.metadata_start)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "mmap")]
impl Reader<Mmap> {
    /// Open a MaxMind DB database file by memory mapping it.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the database file is not modified or
    /// truncated while the `Reader` exists. Modifying or truncating the
    /// file while it is memory-mapped will result in undefined behavior.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "mmap")]
    /// # {
    /// // SAFETY: The database file will not be modified while the reader exists.
    /// let reader = unsafe {
    ///     maxminddb::Reader::open_mmap("test-data/test-data/GeoIP2-City-Test.mmdb")
    /// }.unwrap();
    /// # }
    /// ```
    pub unsafe fn open_mmap<P: AsRef<Path>>(database: P) -> Result<Reader<Mmap>, MaxMindDbError> {
        let file_read = File::open(database)?;
        let mmap = MmapOptions::new()
            .map(&file_read)
            .map_err(MaxMindDbError::Mmap)?;
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
        let metadata_start = find_metadata_start(buf.as_ref())?;
        // find_metadata_start returns the offset after the marker; the marker
        // bytes are not part of the data section and must stay out of limits.
        let data_section_end = metadata_marker_start(metadata_start)?;
        let mut type_decoder = decoder::Decoder::new(&buf.as_ref()[metadata_start..], 0);
        let metadata = Metadata::deserialize(&mut type_decoder)?;
        validate_metadata_for_reader(&metadata)?;

        let search_tree_size =
            search_tree_size_bytes(metadata.node_count as usize, metadata.record_size as usize)?;
        let record_size = metadata.record_size;
        let node_count = metadata.node_count as usize;
        let node_byte_size = record_size as usize / 4;
        let pointer_base = search_tree_size
            .checked_add(DATA_SECTION_SEPARATOR_SIZE)
            .ok_or_else(|| {
                MaxMindDbError::invalid_database(
                    "the MaxMind DB file's search tree extends beyond the file",
                )
            })?;
        validate_search_tree_layout(pointer_base, data_section_end)?;
        let data_section_len = data_section_end - pointer_base;

        let mut reader = Reader {
            buf,
            record_size,
            node_count,
            node_byte_size,
            pointer_base,
            data_section_len,
            metadata_start,
            metadata,
            ipv4_start: 0,
            ipv4_start_bit_depth: 0,
        };
        let (ipv4_start, ipv4_start_bit_depth) = reader.find_ipv4_start();
        reader.ipv4_start = ipv4_start;
        reader.ipv4_start_bit_depth = ipv4_start_bit_depth;

        Ok(reader)
    }

    /// Returns database metadata.
    ///
    /// Metadata is validated when the reader is created and exposed by
    /// reference so it cannot be mutated independently of cached reader state.
    #[inline]
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    /// Lookup an IP address in the database.
    ///
    /// Returns a [`LookupResult`] that can be used to:
    /// - Check if data exists with [`has_data()`](LookupResult::has_data)
    /// - Get the network containing the IP with [`network()`](LookupResult::network)
    /// - Decode the full record with [`decode()`](LookupResult::decode)
    /// - Decode a specific path with [`decode_path()`](LookupResult::decode_path)
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
    ///     // Access nested structs directly - no Option unwrapping needed
    ///     if let Some(name) = city.city.names.english {
    ///         println!("City: {}", name);
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
    /// # use maxminddb::{path, Reader};
    /// # use std::net::IpAddr;
    /// # fn main() -> Result<(), maxminddb::MaxMindDbError> {
    /// let reader = Reader::open_readfile(
    ///     "test-data/test-data/GeoIP2-City-Test.mmdb")?;
    /// let ip: IpAddr = "89.160.20.128".parse().unwrap();
    ///
    /// let result = reader.lookup(ip)?;
    /// let country_code: Option<String> = result.decode_path(&path!["country", "iso_code"])?;
    ///
    /// println!("Country: {:?}", country_code);
    /// # Ok(())
    /// # }
    /// ```
    pub fn lookup(&'de self, address: IpAddr) -> Result<LookupResult<'de, S>, MaxMindDbError> {
        match address {
            IpAddr::V4(v4) => {
                let (pointer, prefix_len) = self.find_address_in_tree_v4(v4.into());

                // For IPv4 addresses in IPv6 databases, adjust prefix_len to reflect
                // the actual bit depth in the tree. The ipv4_start_bit_depth tells us
                // how deep in the IPv6 tree we were when we found the IPv4 subtree.
                let prefix_len = if self.metadata.ip_version == 6 {
                    self.ipv4_start_bit_depth + prefix_len
                } else {
                    prefix_len
                };

                self.lookup_result(pointer, prefix_len as u8, address)
            }
            IpAddr::V6(v6) => {
                if self.metadata.ip_version == 4 {
                    return Err(MaxMindDbError::invalid_input(
                        "cannot look up IPv6 address in IPv4-only database",
                    ));
                }

                let (pointer, prefix_len) = self.find_address_in_tree_v6(v6.into());
                self.lookup_result(pointer, prefix_len as u8, address)
            }
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
    ///     let city_name = city.city.names.english;
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
        if self.metadata.ip_version == 4 && matches!(cidr, IpNetwork::V6(_)) {
            return Err(MaxMindDbError::invalid_input(
                "cannot iterate IPv6 network in IPv4-only database",
            ));
        }
        let ip_address = cidr.network();
        let prefix_len = cidr.prefix() as usize;
        let ip_int = IpInt::new(ip_address);
        let bit_count = ip_int.bit_count();

        let mut node = self.start_node(bit_count);
        let node_count = self.node_count;
        let has_ipv4_subtree = self.has_ipv4_subtree();

        let mut stack: Vec<WithinNode> = Vec::with_capacity(bit_count - prefix_len);

        // `bit_count == 32` means the caller requested an IPv4 CIDR. In an
        // IPv6 database with no IPv4 subtree, `start_node(32)` can already be a
        // terminal IPv6 record reached by walking the all-zero prefix. Do not
        // read that terminal value as a tree node; yield the containing IPv6
        // network instead, matching lookup behavior.
        if bit_count == 32
            && self.metadata.ip_version == 6
            && !has_ipv4_subtree
            && node >= node_count
        {
            stack.push(WithinNode {
                node,
                ip_int: IpInt::V6(0),
                prefix_len: self.ipv4_start_bit_depth,
            });

            return Ok(Within {
                reader: self,
                node_count,
                has_ipv4_subtree,
                stack,
                options,
            });
        }

        // Traverse down the tree to the level that matches the cidr mark
        let mut depth = 0_usize;
        for i in 0..prefix_len {
            // `read_node` is only valid for internal search-tree nodes.
            if node >= node_count {
                // We've hit a data node or dead end before we exhausted our prefix.
                // This means the requested CIDR is contained in a single record.
                break;
            }

            let bit = ip_int.get_bit(i);
            node = self.read_node(node, bit as usize);
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
            has_ipv4_subtree,
            stack,
            options,
        };

        Ok(within)
    }

    // Pointer 0 means "not found" because normalize_lookup_result collapses both
    // the placeholder empty node (`node == node_count`) and an unfinished internal
    // terminal (`node < node_count`, i.e. bits exhausted while still on a tree
    // node) into 0, so neither path reaches resolve_data_pointer with a non-data
    // value.
    #[inline(always)]
    fn lookup_result(
        &'de self,
        pointer: usize,
        prefix_len: u8,
        address: IpAddr,
    ) -> Result<LookupResult<'de, S>, MaxMindDbError> {
        let network_kind = match address {
            IpAddr::V4(_) if self.metadata.ip_version == 6 && self.has_ipv4_subtree() => {
                NetworkKind::V4InV6Subtree
            }
            IpAddr::V4(_) if self.metadata.ip_version == 6 => NetworkKind::V6,
            IpAddr::V4(_) => NetworkKind::V4,
            IpAddr::V6(_) => NetworkKind::V6,
        };
        if pointer == 0 {
            Ok(LookupResult::new_not_found(
                self,
                prefix_len,
                address,
                LookupSource::Lookup,
                network_kind,
            ))
        } else {
            let data_offset = self.resolve_data_pointer(pointer)?;
            Ok(LookupResult::new_found(
                self,
                data_offset,
                prefix_len,
                address,
                LookupSource::Lookup,
                network_kind,
            ))
        }
    }

    #[inline(always)]
    fn find_address_in_tree_v4(&self, ip: u32) -> (usize, usize) {
        let buf = self.buf.as_ref();
        let node_count = self.node_count;

        match self.record_size {
            24 => find_address_in_tree_v4::<RecordSize24>(buf, self.ipv4_start, node_count, ip),
            28 => find_address_in_tree_v4::<RecordSize28>(buf, self.ipv4_start, node_count, ip),
            32 => find_address_in_tree_v4::<RecordSize32>(buf, self.ipv4_start, node_count, ip),
            _ => unreachable!("record_size is validated in Reader::from_source"),
        }
    }

    #[inline(always)]
    fn find_address_in_tree_v6(&self, ip: u128) -> (usize, usize) {
        let buf = self.buf.as_ref();
        let node_count = self.node_count;

        match self.record_size {
            24 => find_address_in_tree_v6::<RecordSize24>(buf, node_count, ip),
            28 => find_address_in_tree_v6::<RecordSize28>(buf, node_count, ip),
            32 => find_address_in_tree_v6::<RecordSize32>(buf, node_count, ip),
            _ => unreachable!("record_size is validated in Reader::from_source"),
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

    #[inline]
    pub(crate) fn has_ipv4_subtree(&self) -> bool {
        self.metadata.ip_version == 6 && self.ipv4_start < self.node_count
    }

    /// Find the IPv4 start node and the bit depth at which it was found.
    /// Returns (node, depth) where depth is how far into the tree we traversed.
    fn find_ipv4_start(&self) -> (usize, usize) {
        if self.metadata.ip_version != 6 {
            return (0, 0);
        }

        // We are looking up an IPv4 address in an IPv6 tree. Skip over the
        // first 96 nodes.
        let mut node: usize = 0;
        for i in 0_u8..96 {
            if node >= self.node_count {
                return (node, i as usize);
            }
            node = self.read_node(node, 0);
        }
        (node, 96)
    }

    #[inline(always)]
    pub(crate) fn read_node(&self, node_number: usize, index: usize) -> usize {
        let buf = self.buf.as_ref();

        match self.record_size {
            24 => RecordSize24::read_node(buf, node_number, index),
            28 => RecordSize28::read_node(buf, node_number, index),
            32 => RecordSize32::read_node(buf, node_number, index),
            _ => unreachable!("record_size is validated in Reader::from_source"),
        }
    }

    /// Resolves a pointer from the search tree to an offset in the data section.
    #[inline]
    pub(crate) fn resolve_data_pointer(&self, pointer: usize) -> Result<usize, MaxMindDbError> {
        let resolved = pointer
            .checked_sub(self.node_count)
            .and_then(|p| p.checked_sub(DATA_SECTION_SEPARATOR_SIZE))
            .ok_or_else(|| {
                MaxMindDbError::invalid_database(
                    "the MaxMind DB file's data pointer resolves to an invalid location",
                )
            })?;
        // Reject offsets at or beyond the marker-excluding data section length.
        if resolved >= self.data_section_len {
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
    /// Note: Verification traverses the entire database and retains visited data
    /// offsets for the duration of the call. It may be slow and use memory
    /// proportional to the number of distinct referenced values on large files.
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
        let metadata_start = find_metadata_start(self.buf.as_ref())?;
        let data_section_end = metadata_marker_start(metadata_start)?;
        self.verify_metadata(data_section_end)?;
        self.verify_database(data_section_end)
    }

    fn verify_metadata(&self, data_section_end: usize) -> Result<(), MaxMindDbError> {
        let m = &self.metadata;

        validate_metadata_for_reader(m)?;
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
        validate_search_tree_layout(self.pointer_base, data_section_end)?;
        Ok(())
    }

    fn verify_database(&self, data_section_end: usize) -> Result<(), MaxMindDbError> {
        let offsets = self.verify_search_tree()?;
        self.verify_data_section_separator()?;
        self.verify_data_section(offsets, data_section_end)
    }

    fn verify_search_tree(&self) -> Result<HashSet<usize>, MaxMindDbError> {
        let mut offsets = HashSet::new();
        let opts = WithinOptions::default().include_networks_without_data();

        // Maximum number of networks we can expect in a valid database.
        // A database with N nodes can have at most 2N data entries (each leaf node
        // can have data). We add some margin for safety.
        let max_iterations = self.node_count.saturating_mul(3);
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
        let separator_start = self.node_count * self.node_byte_size;
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

    fn verify_data_section(
        &self,
        offsets: HashSet<usize>,
        data_section_end: usize,
    ) -> Result<(), MaxMindDbError> {
        let data_section = &self.buf.as_ref()[self.pointer_base..data_section_end];
        let mut verification_state = decoder::VerificationState::default();

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
            if let Err(e) = dec.skip_value_for_verification(&mut verification_state) {
                return Err(MaxMindDbError::invalid_database_at(
                    format!("decoding error: {e}"),
                    offset,
                ));
            }
        }

        Ok(())
    }
}

fn validate_record_size(record_size: u16) -> Result<(), MaxMindDbError> {
    if matches!(record_size, 24 | 28 | 32) {
        Ok(())
    } else {
        Err(MaxMindDbError::invalid_database(format!(
            "record_size - Expected: 24, 28, or 32 Actual: {}",
            record_size
        )))
    }
}

pub(crate) fn validate_metadata_for_reader(metadata: &Metadata) -> Result<(), MaxMindDbError> {
    if metadata.binary_format_major_version != 2 {
        return Err(MaxMindDbError::invalid_database(format!(
            "binary_format_major_version - Expected: 2 Actual: {}",
            metadata.binary_format_major_version
        )));
    }
    // Minor format versions are intended to be forward-compatible.
    if metadata.ip_version != 4 && metadata.ip_version != 6 {
        return Err(MaxMindDbError::invalid_database(format!(
            "ip_version - Expected: 4 or 6 Actual: {}",
            metadata.ip_version
        )));
    }
    if metadata.node_count == 0 {
        return Err(MaxMindDbError::invalid_database(
            "node_count - Expected: positive integer Actual: 0",
        ));
    }
    metadata.build_time()?;
    validate_record_size(metadata.record_size)
}

fn search_tree_size_bytes(node_count: usize, record_size: usize) -> Result<usize, MaxMindDbError> {
    node_count
        .checked_mul(record_size)
        .map(|size| size / 4)
        .ok_or_else(|| {
            MaxMindDbError::invalid_database(
                "search tree size calculation overflowed or is impossibly large",
            )
        })
}

fn validate_search_tree_layout(
    pointer_base: usize,
    data_section_end: usize,
) -> Result<(), MaxMindDbError> {
    if pointer_base > data_section_end {
        return Err(MaxMindDbError::invalid_database(
            "the MaxMind DB file's search tree extends beyond the metadata section",
        ));
    }
    Ok(())
}

trait SearchTreeRecord {
    fn read_node(buf: &[u8], node_number: usize, index: usize) -> usize;
}

struct RecordSize24;

impl SearchTreeRecord for RecordSize24 {
    #[inline(always)]
    fn read_node(buf: &[u8], node_number: usize, index: usize) -> usize {
        let offset = node_number * 6 + index * 3;
        (buf[offset] as usize) << 16 | (buf[offset + 1] as usize) << 8 | buf[offset + 2] as usize
    }
}

struct RecordSize28;

impl SearchTreeRecord for RecordSize28 {
    #[inline(always)]
    fn read_node(buf: &[u8], node_number: usize, index: usize) -> usize {
        let base_offset = node_number * 7;
        let middle = if index == 0 {
            (buf[base_offset + 3] & 0xF0) >> 4
        } else {
            buf[base_offset + 3] & 0x0F
        };
        let offset = base_offset + index * 4;
        (middle as usize) << 24
            | (buf[offset] as usize) << 16
            | (buf[offset + 1] as usize) << 8
            | buf[offset + 2] as usize
    }
}

struct RecordSize32;

impl SearchTreeRecord for RecordSize32 {
    #[inline(always)]
    fn read_node(buf: &[u8], node_number: usize, index: usize) -> usize {
        let offset = node_number * 8 + index * 4;
        (buf[offset] as usize) << 24
            | (buf[offset + 1] as usize) << 16
            | (buf[offset + 2] as usize) << 8
            | buf[offset + 3] as usize
    }
}

#[inline(always)]
fn find_address_in_tree_v4<R: SearchTreeRecord>(
    buf: &[u8],
    start_node: usize,
    node_count: usize,
    ip: u32,
) -> (usize, usize) {
    let mut node = start_node;
    let mut prefix_len = 32;

    for i in 0..32 {
        if node >= node_count {
            prefix_len = i;
            break;
        }
        let bit = ((ip >> (31 - i)) & 1) as usize;
        node = R::read_node(buf, node, bit);
    }

    normalize_lookup_result(node, node_count, prefix_len)
}

#[inline(always)]
fn find_address_in_tree_v6<R: SearchTreeRecord>(
    buf: &[u8],
    node_count: usize,
    ip: u128,
) -> (usize, usize) {
    let mut node = 0;
    let mut prefix_len = 128;

    for i in 0..128 {
        if node >= node_count {
            prefix_len = i;
            break;
        }
        let bit = ((ip >> (127 - i)) & 1) as usize;
        node = R::read_node(buf, node, bit);
    }

    normalize_lookup_result(node, node_count, prefix_len)
}

// Map both "not found" outcomes onto pointer 0:
//   - `node == node_count`: the placeholder empty terminal in the search tree.
//   - `node < node_count`: bits exhausted while still on an internal node
//     (a partially-specified address that did not reach a record).
// Anything strictly greater than `node_count` is a data-section pointer that
// the caller must resolve via `resolve_data_pointer`.
#[inline(always)]
fn normalize_lookup_result(node: usize, node_count: usize, prefix_len: usize) -> (usize, usize) {
    if node <= node_count {
        (0, prefix_len)
    } else {
        (node, prefix_len)
    }
}

fn find_metadata_start(buf: &[u8]) -> Result<usize, MaxMindDbError> {
    memchr::memmem::rfind(buf, METADATA_START_MARKER)
        .map(|x| x + METADATA_START_MARKER.len())
        .ok_or_else(|| {
            MaxMindDbError::invalid_database("could not find MaxMind DB metadata in file")
        })
}

fn metadata_marker_start(metadata_start: usize) -> Result<usize, MaxMindDbError> {
    metadata_start
        .checked_sub(METADATA_START_MARKER.len())
        .ok_or_else(|| MaxMindDbError::invalid_database("invalid metadata marker location"))
}
