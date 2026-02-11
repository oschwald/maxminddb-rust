//! Network iteration types.

use std::cmp::Ordering;
use std::net::IpAddr;

use crate::decoder;
use crate::error::MaxMindDbError;
use crate::reader::Reader;
use crate::result::LookupResult;

/// Options for network iteration.
///
/// Controls which networks are yielded when iterating over the database
/// with [`Reader::within()`] or [`Reader::networks()`].
///
/// # Example
///
/// ```
/// use maxminddb::WithinOptions;
///
/// // Default options (skip aliases, skip networks without data, include empty values)
/// let opts = WithinOptions::default();
///
/// // Include aliased networks (IPv4 networks via IPv6 aliases)
/// let opts = WithinOptions::default().include_aliased_networks();
///
/// // Skip empty values and include networks without data
/// let opts = WithinOptions::default()
///     .skip_empty_values()
///     .include_networks_without_data();
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WithinOptions {
    /// Include IPv4 networks multiple times when accessed via IPv6 aliases.
    include_aliased_networks: bool,
    /// Include networks that have no associated data record.
    include_networks_without_data: bool,
    /// Skip networks whose data is an empty map or empty array.
    skip_empty_values: bool,
}

impl WithinOptions {
    /// Include IPv4 networks multiple times when accessed via IPv6 aliases.
    ///
    /// In IPv6 databases, IPv4 networks are stored at `::0/96`. However, the
    /// same data is accessible through several IPv6 prefixes (e.g.,
    /// `::ffff:0:0/96` for IPv4-mapped IPv6). By default, these aliases are
    /// skipped to avoid yielding the same network multiple times.
    ///
    /// When enabled, the iterator will yield these aliased networks.
    #[must_use]
    pub fn include_aliased_networks(mut self) -> Self {
        self.include_aliased_networks = true;
        self
    }

    /// Include networks that have no associated data record.
    ///
    /// Some tree nodes point to "no data" (the node_count sentinel). By default
    /// these are skipped. When enabled, these networks are yielded and
    /// [`LookupResult::has_data()`] returns `false` for them.
    #[must_use]
    pub fn include_networks_without_data(mut self) -> Self {
        self.include_networks_without_data = true;
        self
    }

    /// Skip networks whose data is an empty map or empty array.
    ///
    /// Some databases store empty maps `{}` or empty arrays `[]` for records
    /// without meaningful data. This option filters them out.
    #[must_use]
    pub fn skip_empty_values(mut self) -> Self {
        self.skip_empty_values = true;
        self
    }
}

#[derive(Debug)]
pub(crate) struct WithinNode {
    pub(crate) node: usize,
    pub(crate) ip_int: IpInt,
    pub(crate) prefix_len: usize,
}

/// Iterator over IP networks within a CIDR range.
///
/// Created by [`Reader::within()`](crate::Reader::within) or
/// [`Reader::networks()`](crate::Reader::networks). Yields
/// [`LookupResult`] for each network in the database that falls
/// within the specified range.
///
/// Networks are yielded in depth-first order through the search tree.
/// Use [`LookupResult::decode()`](crate::LookupResult::decode) to
/// deserialize the data for each result.
///
/// # Example
///
/// ```
/// use maxminddb::{Reader, WithinOptions, geoip2};
///
/// let reader = Reader::open_readfile("test-data/test-data/GeoIP2-City-Test.mmdb").unwrap();
/// for result in reader.within("89.160.20.0/24".parse().unwrap(), Default::default()).unwrap() {
///     let lookup = result.unwrap();
///     if let Some(city) = lookup.decode::<geoip2::City>().unwrap() {
///         println!("{}: {:?}", lookup.network().unwrap(), city.city.names.english);
///     }
/// }
/// ```
#[derive(Debug)]
pub struct Within<'de, S: AsRef<[u8]>> {
    pub(crate) reader: &'de Reader<S>,
    pub(crate) node_count: usize,
    pub(crate) stack: Vec<WithinNode>,
    pub(crate) options: WithinOptions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IpInt {
    V4(u32),
    V6(u128),
}

impl IpInt {
    pub(crate) fn new(ip_addr: IpAddr) -> Self {
        match ip_addr {
            IpAddr::V4(v4) => IpInt::V4(v4.into()),
            IpAddr::V6(v6) => IpInt::V6(v6.into()),
        }
    }

    #[inline(always)]
    pub(crate) fn get_bit(&self, index: usize) -> bool {
        match self {
            IpInt::V4(ip) => (ip >> (31 - index)) & 1 == 1,
            IpInt::V6(ip) => (ip >> (127 - index)) & 1 == 1,
        }
    }

    pub(crate) fn bit_count(&self) -> usize {
        match self {
            IpInt::V4(_) => 32,
            IpInt::V6(_) => 128,
        }
    }

    pub(crate) fn is_ipv4_in_ipv6(&self) -> bool {
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

            // Skip networks that are aliases for the IPv4 network (unless option is set)
            if !self.options.include_aliased_networks
                && self.reader.ipv4_start != 0
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

                    // Check if we should skip empty values
                    if self.options.skip_empty_values {
                        match self.is_empty_value_at(data_offset) {
                            Ok(true) => continue, // Skip empty value
                            Ok(false) => {}       // Not empty, proceed
                            Err(e) => return Some(Err(e)),
                        }
                    }

                    return Some(Ok(LookupResult::new_found(
                        self.reader,
                        data_offset,
                        current.prefix_len as u8,
                        ip_addr,
                    )));
                }
                Ordering::Equal => {
                    // Dead end (no data) - include if option is set
                    if self.options.include_networks_without_data {
                        let ip_addr = ip_int_to_addr(&current.ip_int);
                        return Some(Ok(LookupResult::new_not_found(
                            self.reader,
                            current.prefix_len as u8,
                            ip_addr,
                        )));
                    }
                    // Otherwise skip (current behavior)
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

                    if let Err(e) =
                        self.push_child(current.node, 1, right_ip_int, current.prefix_len + 1)
                    {
                        return Some(Err(e));
                    }
                    // left/0-bit
                    if let Err(e) =
                        self.push_child(current.node, 0, current.ip_int, current.prefix_len + 1)
                    {
                        return Some(Err(e));
                    }
                }
            }
        }
        None
    }
}

impl<'de, S: AsRef<[u8]>> Within<'de, S> {
    fn push_child(
        &mut self,
        parent_node: usize,
        direction: usize,
        ip_int: IpInt,
        prefix_len: usize,
    ) -> Result<(), MaxMindDbError> {
        let node = self.reader.read_node(parent_node, direction)?;
        self.stack.push(WithinNode {
            node,
            ip_int,
            prefix_len,
        });
        Ok(())
    }

    /// Check if the value at the given data offset is an empty map or array.
    fn is_empty_value_at(&self, data_offset: usize) -> Result<bool, MaxMindDbError> {
        let buf = &self.reader.buf.as_ref()[self.reader.pointer_base..];
        let mut dec = decoder::Decoder::new(buf, data_offset);
        let (size, type_num) = dec.peek_type()?;
        match type_num {
            decoder::TYPE_MAP | decoder::TYPE_ARRAY => Ok(size == 0),
            _ => Ok(false), // Non-container types are never "empty"
        }
    }
}

/// Convert IpInt to IpAddr
pub(crate) fn ip_int_to_addr(ip_int: &IpInt) -> IpAddr {
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
