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

const LOOKUP_INDEX_BITS_V4: usize = 8;
const LOOKUP_INDEX_BITS_V6: usize = 4;

// Lookups shift addresses by these widths, and the IPv6 walk shifts its first
// 64-bit word by the stored depth.
const _: () = assert!(LOOKUP_INDEX_BITS_V4 > 0 && LOOKUP_INDEX_BITS_V4 < 32);
const _: () = assert!(LOOKUP_INDEX_BITS_V6 > 0 && LOOKUP_INDEX_BITS_V6 < 64);

#[derive(Clone, Copy)]
#[repr(C, packed)]
struct IndexEntry {
    node: u32,
    depth: u8,
}

struct LookupIndex {
    ipv4: Box<[IndexEntry; 1 << LOOKUP_INDEX_BITS_V4]>,
    ipv6: Box<[IndexEntry; 1 << LOOKUP_INDEX_BITS_V6]>,
}

// The documentation gives these sizes: 1,280 bytes for IPv4 and 80 for IPv6.
const _: () = assert!(std::mem::size_of::<[IndexEntry; 1 << LOOKUP_INDEX_BITS_V4]>() == 1280);
const _: () = assert!(std::mem::size_of::<[IndexEntry; 1 << LOOKUP_INDEX_BITS_V6]>() == 80);

impl LookupIndex {
    // Every slot starts at the root, which is the same as a direct walk.
    fn direct(ipv4_start: usize) -> Self {
        let root = |node: usize| IndexEntry {
            node: node as u32,
            depth: 0,
        };
        Self {
            ipv4: Box::new([root(ipv4_start); 1 << LOOKUP_INDEX_BITS_V4]),
            ipv6: Box::new([root(0); 1 << LOOKUP_INDEX_BITS_V6]),
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
/// - **`unsafe-str-decode`**: Skip UTF-8 validation when deserializing trusted
///   database strings into Rust `str` or `String` values. Cross-runtime format
///   adapters should prefer [`crate::deserialize_any_with_raw_strings()`].
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
    metadata_start: usize,
    lookup_index: LookupIndex,
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
    /// Open a MaxMind DB database from anything that implements AsRef<[u8]>.
    ///
    /// A small immutable prefix index is built automatically. Its tables use
    /// 1,280 bytes for IPv4 and 80 bytes for IPv6. Decoding stays lazy, and
    /// the reader can still be shared across threads.
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
        let metadata_bytes = &buf.as_ref()[metadata_start..];
        let mut type_decoder = decoder::Decoder::new(metadata_bytes, 0);
        let metadata = Metadata::deserialize(&mut type_decoder)
            .map_err(|error| error.with_invalid_database_offset_base(metadata_start))?;
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
            lookup_index: LookupIndex::direct(0),
        };
        let (ipv4_start, ipv4_start_bit_depth) = reader.find_ipv4_start();
        reader.ipv4_start = ipv4_start;
        reader.ipv4_start_bit_depth = ipv4_start_bit_depth;
        reader.build_lookup_index();

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
    #[inline]
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

    /// Iterate over database networks matching a CIDR range.
    ///
    /// Returns an iterator that yields [`LookupResult`] for networks that overlap
    /// the range in the database's search-tree address space, subject to `options`.
    /// Results are not clipped to the requested range. If the range is inside a
    /// larger database network in that address space, the iterator can yield that
    /// enclosing network.
    ///
    /// In IPv6 databases, IPv4 CIDRs are searched under `::/96`. Iteration reports
    /// networks in that IPv4 subtree as IPv4, even for an IPv6 CIDR. If the search
    /// reaches a record before the IPv4 subtree, the result remains IPv6. Returned
    /// networks therefore need not share the CIDR's address family. IPv4-only
    /// databases reject IPv6 CIDRs.
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
    /// A requested range inside a larger database network returns that network:
    /// ```
    /// use maxminddb::Reader;
    ///
    /// let reader = Reader::open_readfile(
    ///     "test-data/test-data/GeoIP2-City-Test.mmdb").unwrap();
    /// let mut results = reader
    ///     .within("89.160.20.128/32".parse().unwrap(), Default::default())
    ///     .unwrap();
    /// let lookup = results.next().unwrap().unwrap();
    /// assert_eq!(lookup.network().unwrap(), "89.160.20.128/25".parse().unwrap());
    /// assert!(results.next().is_none());
    /// ```
    ///
    /// IPv6 CIDRs can return IPv4 networks, and IPv4 CIDRs can return IPv6 networks:
    /// ```
    /// use maxminddb::Reader;
    ///
    /// for (database, cidr, expected) in [
    ///     ("GeoIP2-City-Test.mmdb", "::89.160.20.128/128", "89.160.20.128/25"),
    ///     ("MaxMind-DB-no-ipv4-search-tree.mmdb", "200.0.2.1/32", "::/64"),
    /// ] {
    ///     let reader = Reader::open_readfile(format!("test-data/test-data/{database}")).unwrap();
    ///     let mut results = reader.within(cidr.parse().unwrap(), Default::default()).unwrap();
    ///     let lookup = results.next().unwrap().unwrap();
    ///     assert_eq!(lookup.network().unwrap(), expected.parse().unwrap());
    ///     assert!(results.next().is_none());
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

        let entry = self.lookup_index.ipv4[(ip >> (32 - LOOKUP_INDEX_BITS_V4)) as usize];
        let (node, depth) = (entry.node as usize, entry.depth as usize);

        match self.record_size {
            24 => find_address_in_tree_v4::<RecordSize24>(buf, node, depth, node_count, ip),
            28 => find_address_in_tree_v4::<RecordSize28>(buf, node, depth, node_count, ip),
            32 => find_address_in_tree_v4::<RecordSize32>(buf, node, depth, node_count, ip),
            _ => unreachable!("record_size is validated in Reader::from_source"),
        }
    }

    #[inline(always)]
    fn find_address_in_tree_v6(&self, ip: u128) -> (usize, usize) {
        let buf = self.buf.as_ref();
        let node_count = self.node_count;

        let entry = self.lookup_index.ipv6[(ip >> (128 - LOOKUP_INDEX_BITS_V6)) as usize];
        let (node, depth) = (entry.node as usize, entry.depth as usize);

        match self.record_size {
            24 => find_address_in_tree_v6::<RecordSize24>(buf, node, depth, node_count, ip),
            28 => find_address_in_tree_v6::<RecordSize28>(buf, node, depth, node_count, ip),
            32 => find_address_in_tree_v6::<RecordSize32>(buf, node, depth, node_count, ip),
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
    fn has_ipv4_subtree(&self) -> bool {
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

    fn build_lookup_index(&mut self) {
        // Borrow the tree and the tables separately so the tables allocated in
        // from_source are filled in place.
        let Self {
            buf,
            record_size,
            node_count,
            ipv4_start,
            lookup_index,
            ..
        } = self;
        let tree = buf.as_ref();
        let fill = match record_size {
            24 => fill_lookup_index::<RecordSize24>,
            28 => fill_lookup_index::<RecordSize28>,
            32 => fill_lookup_index::<RecordSize32>,
            _ => unreachable!("record_size is validated in Reader::from_source"),
        };
        fill(
            tree,
            *node_count,
            &mut lookup_index.ipv4[..],
            *ipv4_start,
            0,
        );
        fill(tree, *node_count, &mut lookup_index.ipv6[..], 0, 0);
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
    /// Verification validates each shared target once. For each metadata or
    /// data section, it permits up to eight times the section's byte length in
    /// work units: one per visited value and one per string byte validated.
    /// Exceeding this allowance returns [`MaxMindDbError::ResourceLimit`],
    /// bounding repeated scans of overlapping payloads. Later deserialization
    /// independently applies the per-operation container and payload limits
    /// documented on [`crate::LookupResult::decode()`]. The method is
    /// thread-safe and can be called on an active Reader.
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
        self.verify_metadata(metadata_start, data_section_end)?;
        self.verify_database(data_section_end)
    }

    fn verify_metadata(
        &self,
        metadata_start: usize,
        data_section_end: usize,
    ) -> Result<(), MaxMindDbError> {
        // Metadata deserialization intentionally ignores unknown fields. Verify
        // the original value graph as well so an invalid or cyclic pointer in
        // an unknown field cannot hide behind the cached typed representation.
        let metadata_bytes = &self.buf.as_ref()[metadata_start..];
        let mut decoder = decoder::Decoder::new(metadata_bytes, 0);
        decoder
            .skip_value_for_verification(&mut decoder::VerificationState::new(metadata_bytes.len()))
            .map_err(|error| error.with_invalid_database_offset_base(metadata_start))?;

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
        let mut verification_state = decoder::VerificationState::new(data_section.len());

        // Verify each offset from the search tree points to valid, decodable data
        for &offset in &offsets {
            if offset >= data_section.len() {
                return Err(MaxMindDbError::invalid_database_at(
                    format!(
                        "search tree pointer is beyond data section (len: {})",
                        data_section.len()
                    ),
                    offset,
                )
                .with_invalid_database_offset_base(self.pointer_base));
            }

            let mut dec = decoder::Decoder::new(data_section, offset);

            // Try to skip/decode the value to verify it's valid
            dec.skip_value_for_verification(&mut verification_state)
                .map_err(|error| error.with_invalid_database_offset_base(self.pointer_base))?;
        }

        Ok(())
    }

    // Fuzzing compares indexed lookups with a direct walk from the root.
    #[cfg(any(test, feature = "fuzzing"))]
    #[doc(hidden)]
    pub fn without_lookup_index(mut self) -> Self {
        self.lookup_index = LookupIndex::direct(self.ipv4_start);
        self
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

fn validate_metadata_for_reader(metadata: &Metadata) -> Result<(), MaxMindDbError> {
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

// Each slot gets the node and depth that a direct walk reaches after the
// slot's prefix bits.
fn fill_lookup_index<R: SearchTreeRecord>(
    tree: &[u8],
    node_count: usize,
    entries: &mut [IndexEntry],
    node: usize,
    depth: u8,
) {
    if node >= node_count || entries.len() == 1 {
        // All supported record widths fit in u32. Preserve terminal nodes
        // verbatim, including invalid data pointers, so lookup still
        // reports the same errors and prefix lengths as a direct walk.
        entries.fill(IndexEntry {
            node: node as u32,
            depth,
        });
        return;
    }
    let (left, right) = entries.split_at_mut(entries.len() / 2);
    let (left_node, right_node) = (R::read_node(tree, node, 0), R::read_node(tree, node, 1));
    fill_lookup_index::<R>(tree, node_count, left, left_node, depth + 1);
    fill_lookup_index::<R>(tree, node_count, right, right_node, depth + 1);
}

trait SearchTreeRecord {
    fn read_node(buf: &[u8], node_number: usize, index: usize) -> usize;
}

struct RecordSize24;

impl SearchTreeRecord for RecordSize24 {
    #[inline(always)]
    fn read_node(buf: &[u8], node_number: usize, index: usize) -> usize {
        // Both four-byte windows stay inside the six-byte node. The left
        // child occupies the high three bytes; the right occupies the low three.
        let offset = node_number * 6 + index * 2;
        let bytes: [u8; 4] = buf[offset..offset + 4].try_into().unwrap();
        let word = u32::from_be_bytes(bytes);
        ((word >> ((1 - index) * 8)) & 0x00FF_FFFF) as usize
    }
}

struct RecordSize28;

impl SearchTreeRecord for RecordSize28 {
    #[inline(always)]
    fn read_node(buf: &[u8], node_number: usize, index: usize) -> usize {
        // The left window ends at the shared nibble byte; the right starts
        // there. Each child and its shared nibble fit in a single word.
        let offset = node_number * 7 + index * 3;
        let bytes: [u8; 4] = buf[offset..offset + 4].try_into().unwrap();
        let word = u32::from_be_bytes(bytes);
        if index == 0 {
            // The first three bytes hold bits 23..0, and the shared byte's
            // high nibble holds bits 27..24. Move that nibble above the bytes.
            ((word >> 8) | ((word << 20) & 0x0F00_0000)) as usize
        } else {
            (word & 0x0FFF_FFFF) as usize
        }
    }
}

struct RecordSize32;

impl SearchTreeRecord for RecordSize32 {
    #[inline(always)]
    fn read_node(buf: &[u8], node_number: usize, index: usize) -> usize {
        let offset = node_number * 8 + index * 4;
        let bytes: [u8; 4] = buf[offset..offset + 4].try_into().unwrap();
        u32::from_be_bytes(bytes) as usize
    }
}

#[inline(always)]
fn find_address_in_tree_v4<R: SearchTreeRecord>(
    buf: &[u8],
    start_node: usize,
    start_depth: usize,
    node_count: usize,
    ip: u32,
) -> (usize, usize) {
    let mut node = start_node;
    let mut prefix_len = 32;

    for i in start_depth..32 {
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
    start_node: usize,
    start_depth: usize,
    node_count: usize,
    ip: u128,
) -> (usize, usize) {
    // The first half shifts by start_depth, so it must stay within one word.
    debug_assert!(start_depth < 64);
    let mut node = start_node;
    // Walk 64-bit halves rather than shifting a u128 at every node.
    for (word, base, depth) in [(ip >> 64, 0, start_depth), (ip, 64, 0)] {
        let mut bits = (word as u64) << depth;
        for i in depth..64 {
            if node >= node_count {
                return normalize_lookup_result(node, node_count, base + i);
            }
            node = R::read_node(buf, node, (bits >> 63) as usize);
            bits <<= 1;
        }
    }
    normalize_lookup_result(node, node_count, 128)
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

#[cfg(test)]
mod tests {
    use super::{
        find_address_in_tree_v6, normalize_lookup_result, validate_metadata_for_reader, IndexEntry,
        Reader, RecordSize24, RecordSize28, RecordSize32, SearchTreeRecord, LOOKUP_INDEX_BITS_V4,
        LOOKUP_INDEX_BITS_V6,
    };
    use crate::{MaxMindDbError, PathElement, WithinOptions};
    use ipnetwork::IpNetwork;
    use serde::Deserialize;
    use std::net::IpAddr;

    const TEST_RECORD_SIZES: &[usize] = &[24, 28, 32];

    #[test]
    fn readers_build_prefix_tables_that_skip_tree_levels() {
        // Tables with only root entries still give correct lookups, so check
        // that some slots reach the full index depth.
        let max_depth = |entries: &[IndexEntry]| entries.iter().map(|e| e.depth).max();
        for (family, has_ipv4, has_ipv6) in [
            ("ipv4", true, false),
            ("ipv6", false, true),
            ("mixed", true, true),
        ] {
            let reader = open_test_reader(&format!("MaxMind-DB-test-{family}-24.mmdb"));
            if has_ipv4 {
                let depth = max_depth(&reader.lookup_index.ipv4[..]);
                assert_eq!(depth, Some(LOOKUP_INDEX_BITS_V4 as u8), "{family}");
            }
            if has_ipv6 {
                let depth = max_depth(&reader.lookup_index.ipv6[..]);
                assert_eq!(depth, Some(LOOKUP_INDEX_BITS_V6 as u8), "{family}");
            }
        }
    }

    #[test]
    fn ipv6_walk_matches_bitwise_reference() {
        // The one-bit-at-a-time walk that the two-word walk replaced.
        fn reference(reader: &Reader<Vec<u8>>, ip: u128) -> (usize, usize) {
            let mut node = 0;
            for i in 0..128 {
                if node >= reader.node_count {
                    return normalize_lookup_result(node, reader.node_count, i);
                }
                node = reader.read_node(node, ((ip >> (127 - i)) & 1) as usize);
            }
            normalize_lookup_result(node, reader.node_count, 128)
        }

        for bits in [24, 28, 32] {
            for family in ["ipv6", "mixed"] {
                let name = format!("MaxMind-DB-test-{family}-{bits}.mmdb");
                let indexed = open_test_reader(&name);
                let direct = open_test_reader(&name).without_lookup_index();
                let mut addresses = vec![0, u128::MAX];
                addresses.extend((0..128).map(|bit| 1u128 << bit));
                addresses.extend((0..128).map(|bit| u128::MAX >> bit));
                let options = WithinOptions::default()
                    .include_aliased_networks()
                    .include_networks_without_data();
                for result in indexed.networks(options).unwrap() {
                    match result.unwrap().network().unwrap() {
                        IpNetwork::V4(n) => addresses.extend([
                            u128::from(u32::from(n.network())),
                            u128::from(u32::from(n.broadcast())),
                        ]),
                        IpNetwork::V6(n) => {
                            addresses.extend([u128::from(n.network()), u128::from(n.broadcast())])
                        }
                    }
                }
                for ip in addresses {
                    let expected = reference(&indexed, ip);
                    assert_eq!(
                        indexed.find_address_in_tree_v6(ip),
                        expected,
                        "{name}: {ip:x}"
                    );
                    assert_eq!(
                        direct.find_address_in_tree_v6(ip),
                        expected,
                        "{name}: {ip:x}"
                    );
                }
            }
        }
    }

    #[test]
    fn ipv6_walk_preserves_prefixes_across_word_boundaries() {
        for depth in [1, 8, 12, 13, 32, 63, 64, 65, 96, 127, 128] {
            let node_count = depth;
            let data = node_count + 16;
            let mut tree = Vec::new();
            for node in 0..node_count {
                let left = if node + 1 == node_count {
                    data
                } else {
                    node + 1
                };
                tree.extend_from_slice(&(left as u32).to_be_bytes());
                tree.extend_from_slice(&(node_count as u32).to_be_bytes());
            }
            // Zero follows the complete chain. Diverging at any bit must
            // report exactly that bit's empty-network prefix length.
            assert_eq!(
                find_address_in_tree_v6::<RecordSize32>(&tree, 0, 0, node_count, 0),
                (data, depth)
            );
            for bit in 0..depth {
                let ip = 1u128 << (127 - bit);
                assert_eq!(
                    find_address_in_tree_v6::<RecordSize32>(&tree, 0, 0, node_count, ip),
                    (0, bit + 1)
                );
            }
            if depth > 12 {
                assert_eq!(
                    find_address_in_tree_v6::<RecordSize32>(&tree, 12, 12, node_count, 0),
                    (data, depth)
                );
            }
        }
    }

    #[test]
    fn packed_28_bit_node_matches_spec_layout() {
        // The MMDB specification places each child's most-significant nibble
        // in the shared byte: [left low 24][left high 4 | right high 4][right low 24].
        // https://maxmind.github.io/MaxMind-DB/#28-bits-medium-database-one-node-is-7-bytes
        let node = [0x23, 0x45, 0x67, 0x18, 0x9A, 0xBC, 0xDE];
        assert_eq!(RecordSize28::read_node(&node, 0, 0), 0x0123_4567);
        assert_eq!(RecordSize28::read_node(&node, 0, 1), 0x089A_BCDE);
    }

    #[test]
    fn packed_nodes_round_trip_both_children() {
        type ReadNode = fn(&[u8], usize, usize) -> usize;
        let readers: [(usize, ReadNode); 3] = [
            (24, RecordSize24::read_node),
            (28, RecordSize28::read_node),
            (32, RecordSize32::read_node),
        ];
        for (bits, read_node) in readers {
            let node_size = bits / 4;
            let mask = u32::MAX >> (32 - bits);
            let mut state = 0x4D59_5DF4_D0F3_3173_u64;
            let mut buf = [0u8; 24];
            for sample in 0..65_536 {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                let (left, right) = match sample {
                    0 => (0, mask),
                    1 => (mask, 0),
                    _ => (state as u32 & mask, (state >> 32) as u32 & mask),
                };
                // Exercise every shared-nibble combination for 28-bit records.
                let (left, right) = if bits == 28 && sample >= 2 {
                    (
                        (left & 0x00FF_FFFF) | ((sample as u32 & 15) << 24),
                        (right & 0x00FF_FFFF) | (((sample as u32 >> 4) & 15) << 24),
                    )
                } else {
                    (left, right)
                };
                let node = sample % 3;
                let start = node * node_size;
                let end = start + node_size;
                let encoded = &mut buf[start..end];
                match bits {
                    24 => {
                        encoded[..3].copy_from_slice(&left.to_be_bytes()[1..]);
                        encoded[3..].copy_from_slice(&right.to_be_bytes()[1..]);
                    }
                    28 => {
                        encoded[..3].copy_from_slice(&left.to_be_bytes()[1..]);
                        encoded[3] = ((left >> 20) as u8 & 0xF0) | (right >> 24) as u8;
                        encoded[4..].copy_from_slice(&right.to_be_bytes()[1..]);
                    }
                    32 => {
                        encoded[..4].copy_from_slice(&left.to_be_bytes());
                        encoded[4..].copy_from_slice(&right.to_be_bytes());
                    }
                    _ => unreachable!(),
                }
                // Include unaligned nodes and end the buffer at this node:
                // neither child may require a byte from the following node.
                assert_eq!(read_node(&buf[..end], node, 0), left as usize);
                assert_eq!(read_node(&buf[..end], node, 1), right as usize);
            }
        }
    }

    #[test]
    fn lookup_index_preserves_records_and_networks() {
        for bits in TEST_RECORD_SIZES {
            for family in ["ipv4", "ipv6", "mixed"] {
                let name = format!("MaxMind-DB-test-{family}-{bits}.mmdb");
                let direct = open_test_reader(&name).without_lookup_index();
                let indexed = open_test_reader(&name);
                // Check both ends of every network, including empty networks and
                // IPv4 aliases. This exercises early terminals and exact prefixes.
                let options = WithinOptions::default()
                    .include_aliased_networks()
                    .include_networks_without_data();
                for result in direct.networks(options).unwrap() {
                    let network = result.unwrap().network().unwrap();
                    for ip in [network.network(), network.broadcast()] {
                        let expected = direct.lookup(ip).unwrap();
                        let actual = indexed.lookup(ip).unwrap();
                        assert_eq!(actual.offset(), expected.offset(), "{name}: {ip}");
                        assert_eq!(actual.network().unwrap(), expected.network().unwrap());
                        assert_eq!(
                            actual.decode::<serde_json::Value>().unwrap(),
                            expected.decode::<serde_json::Value>().unwrap()
                        );
                    }
                }
                // Exercise every 8-bit and 4-bit index entry, including different suffixes.
                for prefix in 0..4096u32 {
                    let v4 = IpAddr::from(std::net::Ipv4Addr::from((prefix << 20) | 0x000a_bcde));
                    let expected = direct.lookup(v4).unwrap();
                    let actual = indexed.lookup(v4).unwrap();
                    assert_eq!(actual.offset(), expected.offset());
                    assert_eq!(actual.network().unwrap(), expected.network().unwrap());
                    if direct.metadata().ip_version == 6 {
                        let v6 = IpAddr::from(std::net::Ipv6Addr::from(
                            (u128::from(prefix) << 116) | 0x1234_5678_9abc_def0,
                        ));
                        let expected = direct.lookup(v6).unwrap();
                        let actual = indexed.lookup(v6).unwrap();
                        assert_eq!(actual.offset(), expected.offset());
                        assert_eq!(actual.network().unwrap(), expected.network().unwrap());
                    }
                }
            }
        }
    }

    #[test]
    fn lookup_index_preserves_missing_ipv4_subtree() {
        let direct = open_test_reader("MaxMind-DB-no-ipv4-search-tree.mmdb").without_lookup_index();
        let indexed = open_test_reader("MaxMind-DB-no-ipv4-search-tree.mmdb");
        for address in [
            "0.0.0.0",
            "1.1.1.1",
            "255.255.255.255",
            "::",
            "::1",
            "ffff::",
        ] {
            let ip = address.parse().unwrap();
            let expected = direct.lookup(ip).unwrap();
            let actual = indexed.lookup(ip).unwrap();
            assert_eq!(actual.offset(), expected.offset());
            assert_eq!(actual.network().unwrap(), expected.network().unwrap());
        }
    }

    #[test]
    fn lookup_index_preserves_corrupt_tree_behavior() {
        let addresses = [
            "0.0.0.0",
            "1.2.3.4",
            "255.255.255.255",
            "::",
            "::1.2.3.4",
            "8000::",
            "ffff::",
        ];
        for &bits in TEST_RECORD_SIZES {
            for family in ["ipv4", "ipv6", "mixed"] {
                let name = format!("MaxMind-DB-test-{family}-{bits}.mmdb");
                let original = open_test_reader(&name);
                let node_count = original.metadata().node_count as usize;
                let mut patched_depths = Vec::new();
                // Patch the root, a node inside the index depth, and nodes on the
                // IPv4 path of IPv6 trees, including the IPv4 start and a node below it.
                for depth in [0, 2, 50, 96, 98] {
                    let Some(node) = zero_path_node(&original, depth) else {
                        continue;
                    };
                    patched_depths.push(depth);
                    // Cycle, empty terminal, separator pointers, and out-of-bounds pointers.
                    for (pointer, sides) in [
                        0,
                        node_count,
                        node_count + 1,
                        node_count + 15,
                        (1 << bits) - 1,
                    ]
                    .into_iter()
                    .flat_map(|pointer| [&[0][..], &[1], &[0, 1]].map(|sides| (pointer, sides)))
                    {
                        let mut bytes = original.buf.clone();
                        for &side in sides {
                            write_record(&mut bytes, bits, node, side, pointer);
                        }
                        let direct = Reader::from_source(bytes.as_slice())
                            .unwrap()
                            .without_lookup_index();
                        for &side in sides {
                            assert_eq!(
                                direct.read_node(node, side),
                                pointer,
                                "{name}: patch failed"
                            );
                        }
                        let indexed = Reader::from_source(bytes.as_slice()).unwrap();
                        for address in addresses {
                            let ip = address.parse().unwrap();
                            match (direct.lookup(ip), indexed.lookup(ip)) {
                                (Ok(expected), Ok(actual)) => {
                                    assert_eq!(actual.offset(), expected.offset());
                                    assert_eq!(
                                        actual.network().unwrap(),
                                        expected.network().unwrap()
                                    );
                                }
                                (Err(expected), Err(actual)) => {
                                    assert_eq!(actual.to_string(), expected.to_string())
                                }
                                _ => panic!(
                                    "{name}: index changed lookup of {ip} after patching \
                                     sides {sides:?} at depth {depth} with {pointer}"
                                ),
                            }
                        }
                    }
                }
                if family == "mixed" {
                    assert!(patched_depths.contains(&98), "{name}: {patched_depths:?}");
                }
            }
        }
    }

    #[test]
    fn test_metadata_validation_rejects_hard_invariants() {
        let reader = open_test_reader("MaxMind-DB-test-ipv4-24.mmdb");
        let metadata = reader.metadata();

        let mut invalid = metadata.clone();
        invalid.binary_format_major_version = 3;
        assert!(matches!(
            validate_metadata_for_reader(&invalid),
            Err(MaxMindDbError::InvalidDatabase { .. })
        ));

        let mut future_minor = metadata.clone();
        future_minor.binary_format_minor_version = u16::MAX;
        validate_metadata_for_reader(&future_minor).unwrap();

        let mut invalid = metadata.clone();
        invalid.ip_version = 5;
        assert!(matches!(
            validate_metadata_for_reader(&invalid),
            Err(MaxMindDbError::InvalidDatabase { .. })
        ));

        let mut invalid = metadata.clone();
        invalid.node_count = 0;
        assert!(matches!(
            validate_metadata_for_reader(&invalid),
            Err(MaxMindDbError::InvalidDatabase { .. })
        ));
    }

    #[test]
    fn test_resolve_data_pointer_rejects_small_pointer() {
        let reader = open_test_reader("MaxMind-DB-test-ipv4-24.mmdb");
        let err = reader
            .resolve_data_pointer(reader.metadata().node_count as usize)
            .unwrap_err();

        assert!(matches!(err, MaxMindDbError::InvalidDatabase { .. }));
    }

    #[test]
    fn test_skip_empty_values_reports_absolute_file_offset() {
        let source_path = "test-data/test-data/MaxMind-DB-test-ipv4-24.mmdb";
        let original = Reader::open_readfile(source_path).unwrap();
        let data_offset = original
            .lookup("1.1.1.32".parse().unwrap())
            .unwrap()
            .offset()
            .unwrap();
        let record_start = original.pointer_base + data_offset;
        let expected_offset = original.pointer_base + original.data_section_len;
        let pointer = four_byte_pointer(original.data_section_len);
        let mut bytes = std::fs::read(source_path).unwrap();
        bytes[record_start..record_start + pointer.len()].copy_from_slice(&pointer);

        let reader = Reader::from_source(bytes).unwrap();
        let options = WithinOptions::default().skip_empty_values();
        let err = reader
            .networks(options)
            .unwrap()
            .find_map(Result::err)
            .expect("iterator should encounter the malformed record");

        assert!(matches!(
            err,
            MaxMindDbError::InvalidDatabase {
                offset: Some(offset),
                ..
            } if offset == expected_offset
        ));
    }

    #[test]
    fn test_verify_rejects_invalid_pointer_in_unknown_metadata_field() {
        let source_path = "test-data/test-data/MaxMind-DB-test-ipv4-24.mmdb";
        let original = Reader::open_readfile(source_path).unwrap();
        let metadata_start = original.metadata_start;
        let mut bytes = std::fs::read(source_path).unwrap();

        assert_eq!(bytes[metadata_start], 0xe9, "unexpected metadata map size");
        bytes[metadata_start] = 0xea; // add one map entry
        bytes.push(0x47); // seven-byte string key
        bytes.extend_from_slice(b"unknown");
        bytes.extend_from_slice(&[0x20, 0xff]); // pointer beyond the metadata buffer

        // Typed metadata parsing skips the unknown value without following its
        // pointer, so normal reader construction remains lazy.
        let reader = Reader::from_source(bytes).unwrap();
        let err = reader.verify().unwrap_err();

        assert!(matches!(
            err,
            MaxMindDbError::InvalidDatabase {
                offset: Some(offset),
                ..
            } if offset == metadata_start + 255
        ));
    }

    #[test]
    fn test_verify_bounds_overlapping_strings_in_unknown_metadata() {
        let source_path = "test-data/test-data/MaxMind-DB-test-ipv4-24.mmdb";
        let original = Reader::open_readfile(source_path).unwrap();
        let metadata_start = original.metadata_start;
        let mut bytes = std::fs::read(source_path).unwrap();
        assert_eq!(bytes[metadata_start], 0xe9);
        bytes[metadata_start] = 0xea;
        bytes.push(0x47);
        bytes.extend_from_slice(b"unknown");
        bytes.extend_from_slice(&four_byte_pointer(bytes.len() + 5 - metadata_start));

        const COUNT: usize = 64;
        bytes.extend_from_slice(&[0x1d, 0x04, (COUNT - 29) as u8]);
        let strings_offset = bytes.len() + COUNT * 5 - metadata_start;
        for index in 0..COUNT {
            bytes.extend_from_slice(&four_byte_pointer(strings_offset + index * 4));
        }
        // String headers are valid ASCII within the overlapping payloads. A
        // roughly 133 KiB file would otherwise require over 8 MiB of UTF-8 scans.
        for _ in 0..COUNT {
            bytes.extend_from_slice(&[0x5f, 0x01, 0x00, 0x00]);
        }
        bytes.resize(bytes.len() + 65_821 + 65_536, b'a');

        let reader = Reader::from_source(bytes).unwrap();
        let err = reader.verify().unwrap_err();
        assert!(matches!(
            err,
            MaxMindDbError::ResourceLimit { message, offset: Some(offset), path: None }
                if message == "exceeded maximum verification work"
                    && offset == strings_offset + 8 * 4 + 4
        ));
    }

    #[test]
    fn test_verify_shares_work_allowance_across_data_roots() {
        let source_path = "test-data/test-data/MaxMind-DB-test-ipv4-24.mmdb";
        let source = std::fs::read(source_path).unwrap();
        let original = Reader::from_source(source.as_slice()).unwrap();
        assert_eq!(original.metadata().record_size, 24);
        let node_count = original.metadata().node_count as usize;

        const ROOT_COUNT: usize = 16;
        let make_reader = |distinct_roots: usize| {
            let mut bytes = source[..original.pointer_base].to_vec();
            let mut leaf_count = 0;
            for record in bytes[..node_count * 6].as_chunks_mut::<3>().0 {
                let pointer = u32::from_be_bytes([0, record[0], record[1], record[2]]) as usize;
                if pointer >= node_count {
                    // Preserve the tree, redirecting both empty and data leaves
                    // to the overlapping string headers in the new data section.
                    let offset = (leaf_count % distinct_roots) * 4;
                    let target = u32::try_from(node_count + 16 + offset).unwrap();
                    assert!(target <= 0x00ff_ffff);
                    record.copy_from_slice(&target.to_be_bytes()[1..]);
                    leaf_count += 1;
                }
            }
            assert!(leaf_count >= ROOT_COUNT);

            // Each string has a 131,357-byte payload, and its header is valid
            // ASCII inside earlier strings. Nine scans exceed the allowance for
            // this data section, including all headers and the trailing payload.
            for _ in 0..ROOT_COUNT {
                bytes.extend_from_slice(&[0x5f, 0x01, 0x00, 0x00]);
            }
            bytes.resize(bytes.len() + 65_821 + 65_536, b'a');
            bytes.extend_from_slice(&source[original.pointer_base + original.data_section_len..]);
            Reader::from_source(bytes).unwrap()
        };

        // Repeated references to one root fit because verification caches it.
        make_reader(1).verify().unwrap();
        let err = make_reader(ROOT_COUNT).verify().unwrap_err();
        // Root iteration uses a HashSet, so the failing offset is unspecified.
        assert!(matches!(
            err,
            MaxMindDbError::ResourceLimit { message, .. }
                if message == "exceeded maximum verification work"
        ));
    }

    #[test]
    fn test_from_source_reports_absolute_metadata_offset() {
        let source_path = "test-data/test-data/MaxMind-DB-test-ipv4-24.mmdb";
        let original = Reader::open_readfile(source_path).unwrap();
        let metadata_start = original.metadata_start;
        let mut bytes = std::fs::read(source_path).unwrap();
        let metadata_len = bytes.len() - metadata_start;
        let database_type = b"database_type";
        let key_start = bytes[metadata_start..]
            .windows(database_type.len())
            .position(|window| window == database_type)
            .map(|offset| metadata_start + offset)
            .expect("metadata should contain database_type");
        let value_start = key_start + database_type.len();
        let pointer = four_byte_pointer(metadata_len);
        bytes[value_start..value_start + pointer.len()].copy_from_slice(&pointer);

        let err = Reader::from_source(bytes).unwrap_err();
        assert!(matches!(
            err,
            MaxMindDbError::InvalidDatabase {
                offset: Some(offset),
                ..
            } if offset == metadata_start + metadata_len
        ));
    }

    #[test]
    fn test_rejects_data_pointer_to_metadata_marker() {
        let source_path = "test-data/test-data/MaxMind-DB-test-ipv4-24.mmdb";
        let reader = Reader::open_readfile(source_path).unwrap();
        assert_eq!(reader.metadata().record_size, 24);

        let pointer = reader.metadata().node_count as usize + 16 + reader.data_section_len;
        assert!(pointer <= 0x00ff_ffff);

        let mut bytes = std::fs::read(source_path).unwrap();
        for record_start in [0, 3] {
            let record = &mut bytes[record_start..record_start + 3];
            record[0] = ((pointer >> 16) & 0xff) as u8;
            record[1] = ((pointer >> 8) & 0xff) as u8;
            record[2] = (pointer & 0xff) as u8;
        }

        let reader = Reader::from_source(bytes).unwrap();
        let err = reader.lookup("1.1.1.1".parse().unwrap()).unwrap_err();
        assert!(
            matches!(err, MaxMindDbError::InvalidDatabase { .. }),
            "Expected InvalidDatabase error for marker pointer, got {err:?}"
        );

        let result = reader.verify();
        assert!(
            matches!(result, Err(MaxMindDbError::InvalidDatabase { .. })),
            "Expected InvalidDatabase error for marker pointer during verify, got {result:?}"
        );
    }

    #[test]
    fn test_verify_rejects_truncated_scalar_value() {
        let source_path = "test-data/test-data/MaxMind-DB-test-ipv4-24.mmdb";
        let reader = open_test_reader("MaxMind-DB-test-ipv4-24.mmdb");
        let lookup = reader.lookup("1.1.1.32".parse().unwrap()).unwrap();
        let data_offset = lookup.offset().expect("expected data offset");
        let mut bytes = std::fs::read(source_path).unwrap();
        let record_start = reader.pointer_base + data_offset;
        let string_value = b"1.1.1.32";
        let relative_value_offset = bytes[record_start..]
            .windows(string_value.len())
            .position(|window| window == string_value)
            .expect("expected terminal string payload in fixture record");
        let string_ctrl_offset = record_start + relative_value_offset - 1;
        assert_eq!(
            bytes[string_ctrl_offset], 0x48,
            "unexpected string control byte in source fixture"
        );

        // Inflate the terminal string from length 8 to length 28 without adding
        // bytes, so verification must catch the truncated payload.
        bytes[string_ctrl_offset] = 0x5c;

        let reader = Reader::from_source(bytes).unwrap();
        let result = reader.verify();
        assert!(
            matches!(
                result,
                Err(MaxMindDbError::InvalidDatabase {
                    offset: Some(offset),
                    ..
                }) if offset == string_ctrl_offset + 1
            ),
            "Expected InvalidDatabase error for truncated scalar payload, got {:?}",
            result
        );
    }

    #[test]
    fn test_decode_rejects_truncated_ignored_scalar_value() {
        let source_path = "test-data/test-data/MaxMind-DB-test-ipv4-24.mmdb";
        let reader = open_test_reader("MaxMind-DB-test-ipv4-24.mmdb");
        let lookup = reader.lookup("1.1.1.32".parse().unwrap()).unwrap();
        let data_offset = lookup.offset().expect("expected data offset");
        let mut bytes = std::fs::read(source_path).unwrap();
        let record_start = reader.pointer_base + data_offset;
        let string_value = b"1.1.1.32";
        let relative_value_offset = bytes[record_start..]
            .windows(string_value.len())
            .position(|window| window == string_value)
            .expect("expected terminal string payload in fixture record");
        let string_ctrl_offset = record_start + relative_value_offset - 1;
        assert_eq!(
            bytes[string_ctrl_offset], 0x48,
            "unexpected string control byte in source fixture"
        );

        // Inflate the terminal string from length 8 to length 28 without adding
        // bytes. Decoding into a struct with no fields forces serde to skip the
        // corrupt value as unknown data.
        bytes[string_ctrl_offset] = 0x5c;

        #[derive(Deserialize, Debug)]
        struct Empty {}

        let reader = Reader::from_source(bytes).unwrap();
        let lookup = reader.lookup("1.1.1.32".parse().unwrap()).unwrap();
        let err = lookup.decode::<Empty>().unwrap_err();

        assert!(matches!(
            err,
            MaxMindDbError::InvalidDatabase {
                offset: Some(offset),
                ..
            } if offset == string_ctrl_offset + 1
        ));

        let err = lookup
            .decode_path::<String>(&[PathElement::Key("ip")])
            .unwrap_err();
        assert!(matches!(
            err,
            MaxMindDbError::InvalidDatabase {
                offset: Some(offset),
                ..
            } if offset == string_ctrl_offset + 1
        ));
    }

    #[test]
    fn test_network_iteration_rejects_internal_node_cycle() {
        let mut reader = open_test_reader("MaxMind-DB-test-ipv4-24.mmdb");

        // Make both branches of the root node point back to the root. Opening the
        // original database already populated all layout invariants, so this
        // isolates iterator behavior on a corrupt tree without building a fixture.
        reader.buf[..6].fill(0);

        let err = reader
            .networks(Default::default())
            .unwrap()
            .next()
            .expect("cyclic tree should yield an error")
            .unwrap_err();
        assert!(matches!(err, MaxMindDbError::InvalidDatabase { .. }));
        assert!(err.to_string().contains("address bit length"));
    }

    #[test]
    fn test_verify_follows_and_rejects_invalid_data_pointers() {
        let mut reader = open_test_reader("MaxMind-DB-test-ipv4-24.mmdb");
        let data_offset = reader
            .lookup("1.1.1.1".parse().unwrap())
            .unwrap()
            .offset()
            .unwrap();
        let record_start = reader.pointer_base + data_offset;

        // Replace the record with a four-byte data pointer to u32::MAX, which is
        // outside this database's data section.
        reader.buf[record_start..record_start + 5].copy_from_slice(&[0x38, 0xff, 0xff, 0xff, 0xff]);

        let err = reader.verify().unwrap_err();
        assert!(matches!(err, MaxMindDbError::InvalidDatabase { .. }));
        assert!(err.to_string().contains("unexpected end of buffer"));
    }

    #[test]
    fn test_decode_path_navigation_shares_logical_value_budget_across_hops() {
        let mut reader = open_test_reader("MaxMind-DB-test-ipv4-24.mmdb");
        let ip = "1.1.1.1".parse().unwrap();
        let data_offset = reader.lookup(ip).unwrap().offset().unwrap();
        let record_start = reader.pointer_base + data_offset;

        // Replace the record with two nested arrays that each declare 32,768
        // children. Either declaration fits independently, but their cumulative
        // reservations plus the top-level value exceed the 65,536-value budget by
        // one. The second header is reached through a real, nonempty path.
        let array_header = [0x1e, 0x04, 0x7e, 0xe3];
        reader.buf[record_start..record_start + 4].copy_from_slice(&array_header);
        reader.buf[record_start + 4..record_start + 8].copy_from_slice(&array_header);

        let err = reader
            .lookup(ip)
            .unwrap()
            .decode_path::<u16>(&[PathElement::Index(0), PathElement::Index(0)])
            .unwrap_err();

        assert!(
            matches!(
                &err,
                MaxMindDbError::ResourceLimit {
                    message,
                    path: Some(path),
                    ..
                } if message.contains("maximum number of data structure values")
                    && path == "/0/0"
            ),
            "unexpected cumulative decode_path result: {err}"
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

    fn open_test_reader(name: &str) -> Reader<Vec<u8>> {
        Reader::open_readfile(format!("test-data/test-data/{name}"))
            .unwrap_or_else(|e| panic!("failed to open test database '{name}': {e}"))
    }

    /// Returns the node at `depth` on the all-zero path, if the path reaches it.
    fn zero_path_node(reader: &Reader<Vec<u8>>, depth: usize) -> Option<usize> {
        let mut node = 0;
        for _ in 0..depth {
            node = reader.read_node(node, 0);
            if node >= reader.metadata().node_count as usize {
                return None;
            }
        }
        Some(node)
    }

    fn write_record(bytes: &mut [u8], record_size: usize, node: usize, side: usize, value: usize) {
        let value = u32::try_from(value).unwrap().to_be_bytes();
        match record_size {
            24 => {
                let offset = node * 6 + side * 3;
                bytes[offset..offset + 3].copy_from_slice(&value[1..]);
            }
            28 => {
                // The middle byte holds the high nibble of each record.
                let offset = node * 7;
                let shared = offset + 3;
                if side == 0 {
                    bytes[offset..offset + 3].copy_from_slice(&value[1..]);
                    bytes[shared] = (bytes[shared] & 0x0f) | (value[0] << 4);
                } else {
                    bytes[shared + 1..shared + 4].copy_from_slice(&value[1..]);
                    bytes[shared] = (bytes[shared] & 0xf0) | (value[0] & 0x0f);
                }
            }
            32 => {
                let offset = node * 8 + side * 4;
                bytes[offset..offset + 4].copy_from_slice(&value);
            }
            _ => unreachable!("test record sizes are 24, 28, or 32"),
        }
    }

    fn four_byte_pointer(target: usize) -> [u8; 5] {
        let target = u32::try_from(target).expect("test pointer target must fit in four bytes");
        let bytes = target.to_be_bytes();
        [0x38, bytes[0], bytes[1], bytes[2], bytes[3]]
    }
}
