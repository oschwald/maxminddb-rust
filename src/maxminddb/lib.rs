#![crate_name = "maxminddb"]
#![crate_type = "dylib"]
#![crate_type = "rlib"]
#![deny(
    trivial_casts,
    trivial_numeric_casts,
    unstable_features,
    unused_import_braces
)]

#[macro_use]
extern crate log;

#[cfg(feature = "mmap")]
extern crate memmap;

#[macro_use]
extern crate serde;

#[macro_use]
extern crate serde_derive;

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::net::IpAddr;

#[cfg(feature = "mmap")]
use memmap::Mmap;
#[cfg(feature = "mmap")]
use memmap::MmapOptions;
use serde::{de, Deserialize};
#[cfg(feature = "mmap")]
use std::fs::File;
use std::path::Path;

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
        MaxMindDBError::IoError(err.description().to_owned())
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

type BinaryDecodeResult<T> = (Result<T, MaxMindDBError>, usize);

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

struct BinaryDecoder<T: AsRef<[u8]>> {
    buf: T,
    pointer_base: usize,
}

impl<T: AsRef<[u8]>> BinaryDecoder<T> {
    fn decode_array(&self, size: usize, offset: usize) -> BinaryDecodeResult<decoder::DataRecord> {
        let mut array = Vec::new();
        let mut new_offset = offset;

        for _ in 0..size {
            let (val, tmp_offset) = match self.decode(new_offset) {
                (Ok(v), os) => (v, os),
                (Err(e), os) => return (Err(e), os),
            };
            new_offset = tmp_offset;
            array.push(val);
        }
        (Ok(decoder::DataRecord::Array(array)), new_offset)
    }

    fn decode_bool(&self, size: usize, offset: usize) -> BinaryDecodeResult<decoder::DataRecord> {
        match size {
            0 | 1 => (Ok(decoder::DataRecord::Boolean(size != 0)), offset),
            s => (
                Err(MaxMindDBError::InvalidDatabaseError(format!(
                    "float of size {:?}",
                    s
                ))),
                0,
            ),
        }
    }

    fn decode_bytes(&self, size: usize, offset: usize) -> BinaryDecodeResult<decoder::DataRecord> {
        let new_offset = offset + size;
        let u8_slice = &self.buf.as_ref()[offset..new_offset];

        let bytes = u8_slice
            .iter()
            .map(|&b| decoder::DataRecord::Byte(b))
            .collect();

        (Ok(decoder::DataRecord::Array(bytes)), new_offset)
    }

    fn decode_float(&self, size: usize, offset: usize) -> BinaryDecodeResult<decoder::DataRecord> {
        match size {
            4 => {
                let new_offset = offset + size;

                let value = self.buf.as_ref()[offset..new_offset]
                    .iter()
                    .fold(0u32, |acc, &b| (acc << 8) | u32::from(b));
                let float_value: f32 = f32::from_bits(value);
                (Ok(decoder::DataRecord::Float(float_value)), new_offset)
            }
            s => (
                Err(MaxMindDBError::InvalidDatabaseError(format!(
                    "float of size {:?}",
                    s
                ))),
                0,
            ),
        }
    }

    fn decode_double(&self, size: usize, offset: usize) -> BinaryDecodeResult<decoder::DataRecord> {
        match size {
            8 => {
                let new_offset = offset + size;

                let value = self.buf.as_ref()[offset..new_offset]
                    .iter()
                    .fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
                let float_value: f64 = f64::from_bits(value);
                (Ok(decoder::DataRecord::Double(float_value)), new_offset)
            }
            s => (
                Err(MaxMindDBError::InvalidDatabaseError(format!(
                    "double of size {:?}",
                    s
                ))),
                0,
            ),
        }
    }

    fn decode_uint64(&self, size: usize, offset: usize) -> BinaryDecodeResult<decoder::DataRecord> {
        match size {
            s if s <= 8 => {
                let new_offset = offset + size;

                let value = self.buf.as_ref()[offset..new_offset]
                    .iter()
                    .fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
                (Ok(decoder::DataRecord::Uint64(value)), new_offset)
            }
            s => (
                Err(MaxMindDBError::InvalidDatabaseError(format!(
                    "u64 of size {:?}",
                    s
                ))),
                0,
            ),
        }
    }

    fn decode_uint32(&self, size: usize, offset: usize) -> BinaryDecodeResult<decoder::DataRecord> {
        match size {
            s if s <= 4 => match self.decode_uint64(size, offset) {
                (Ok(decoder::DataRecord::Uint64(u)), o) => {
                    (Ok(decoder::DataRecord::Uint32(u as u32)), o)
                }
                e => e,
            },
            s => (
                Err(MaxMindDBError::InvalidDatabaseError(format!(
                    "u32 of size {:?}",
                    s
                ))),
                0,
            ),
        }
    }

    fn decode_uint16(&self, size: usize, offset: usize) -> BinaryDecodeResult<decoder::DataRecord> {
        match size {
            s if s <= 4 => match self.decode_uint64(size, offset) {
                (Ok(decoder::DataRecord::Uint64(u)), o) => {
                    (Ok(decoder::DataRecord::Uint16(u as u16)), o)
                }
                e => e,
            },
            s => (
                Err(MaxMindDBError::InvalidDatabaseError(format!(
                    "u16 of size {:?}",
                    s
                ))),
                0,
            ),
        }
    }

    fn decode_int(&self, size: usize, offset: usize) -> BinaryDecodeResult<decoder::DataRecord> {
        match size {
            s if s <= 4 => {
                let new_offset = offset + size;

                let value = self.buf.as_ref()[offset..new_offset]
                    .iter()
                    .fold(0i32, |acc, &b| (acc << 8) | i32::from(b));
                (Ok(decoder::DataRecord::Int32(value)), new_offset)
            }
            s => (
                Err(MaxMindDBError::InvalidDatabaseError(format!(
                    "int32 of size {:?}",
                    s
                ))),
                0,
            ),
        }
    }

    fn decode_map(&self, size: usize, offset: usize) -> BinaryDecodeResult<decoder::DataRecord> {
        let mut values = Box::new(BTreeMap::new());
        let mut new_offset = offset;

        for _ in 0..size {
            let (key, val_offset) = match self.decode(new_offset) {
                (Ok(v), os) => (v, os),
                (Err(e), os) => return (Err(e), os),
            };
            let (val, tmp_offset) = match self.decode(val_offset) {
                (Ok(v), os) => (v, os),
                (Err(e), os) => return (Err(e), os),
            };
            new_offset = tmp_offset;

            let str_key = match key {
                decoder::DataRecord::String(s) => s,
                v => {
                    return (
                        Err(MaxMindDBError::InvalidDatabaseError(format!(
                            "unexpected map \
                             key type {:?}",
                            v
                        ))),
                        0,
                    )
                }
            };
            values.insert(str_key, val);
        }
        (Ok(decoder::DataRecord::Map(values)), new_offset)
    }

    fn decode_pointer(
        &self,
        size: usize,
        offset: usize,
    ) -> BinaryDecodeResult<decoder::DataRecord> {
        let pointer_value_offset = [0, 0, 2048, 526_336, 0];
        let pointer_size = ((size >> 3) & 0x3) + 1;
        let new_offset = offset + pointer_size;
        let pointer_bytes = &self.buf.as_ref()[offset..new_offset];

        let base = if pointer_size == 4 {
            0
        } else {
            (size & 0x7) as u8
        };
        let unpacked = to_usize(base, pointer_bytes);
        let pointer = unpacked + self.pointer_base + pointer_value_offset[pointer_size];

        // XXX fix cast. Use usize everywhere?
        let (result, _) = self.decode(pointer);
        (result, new_offset)
    }

    fn decode_string(&self, size: usize, offset: usize) -> BinaryDecodeResult<decoder::DataRecord> {
        use std::str::from_utf8;

        let new_offset: usize = offset + size;
        let bytes = &self.buf.as_ref()[offset..new_offset];
        match from_utf8(bytes) {
            Ok(v) => (Ok(decoder::DataRecord::String(v.to_owned())), new_offset),
            Err(_) => (
                Err(MaxMindDBError::InvalidDatabaseError(
                    "error decoding string".to_owned(),
                )),
                new_offset,
            ),
        }
    }

    fn decode(&self, offset: usize) -> BinaryDecodeResult<decoder::DataRecord> {
        let mut new_offset = offset + 1;
        let ctrl_byte = self.buf.as_ref()[offset];

        let mut type_num = ctrl_byte >> 5;

        // Extended type
        if type_num == 0 {
            type_num = self.buf.as_ref()[new_offset] + 7;
            new_offset += 1;
        }

        let (size, value_offset) = self.size_from_ctrl_byte(ctrl_byte, new_offset, type_num);
        self.decode_from_type(type_num, size, value_offset)
    }

    fn size_from_ctrl_byte(&self, ctrl_byte: u8, offset: usize, type_num: u8) -> (usize, usize) {
        let mut size = (ctrl_byte & 0x1f) as usize;
        // extended
        if type_num == 0 {
            return (size, offset);
        }

        let bytes_to_read = if size > 28 { size - 28 } else { 0 };

        let new_offset = offset + bytes_to_read;
        let size_bytes = &self.buf.as_ref()[offset..new_offset];

        size = match size {
            s if s < 29 => s,
            29 => 29usize + size_bytes[0] as usize,
            30 => 285usize + to_usize(0, size_bytes),
            _ => 65_821usize + to_usize(0, size_bytes),
        };
        (size, new_offset)
    }

    fn decode_from_type(
        &self,
        data_type: u8,
        size: usize,
        offset: usize,
    ) -> BinaryDecodeResult<decoder::DataRecord> {
        match data_type {
            1 => self.decode_pointer(size, offset),
            2 => self.decode_string(size, offset),
            3 => self.decode_double(size, offset),
            4 => self.decode_bytes(size, offset),
            5 => self.decode_uint16(size, offset),
            6 => self.decode_uint32(size, offset),
            7 => self.decode_map(size, offset),
            8 => self.decode_int(size, offset),
            9 => self.decode_uint64(size, offset),
            // XXX - this is u128. The return value for this is subject to change.
            10 => self.decode_bytes(size, offset),
            11 => self.decode_array(size, offset),
            14 => self.decode_bool(size, offset),
            15 => self.decode_float(size, offset),
            u => (
                Err(MaxMindDBError::InvalidDatabaseError(format!(
                    "Unknown data type: {:?}",
                    u
                ))),
                offset,
            ),
        }
    }
}

/// A reader for the MaxMind DB format. The lifetime `'data` is tied to the lifetime of the underlying buffer holding the contents of the database file.
pub struct Reader<S: AsRef<[u8]>> {
    decoder: BinaryDecoder<S>,
    pub metadata: Metadata,
    ipv4_start: usize,
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

        let metadata_decoder = BinaryDecoder {
            buf,
            pointer_base: metadata_start,
        };

        let raw_metadata = match metadata_decoder.decode(metadata_start) {
            (Ok(m), _) => m,
            m => {
                return Err(MaxMindDBError::InvalidDatabaseError(format!(
                    "metadata of wrong \
                     type: {:?}",
                    m
                )))
            }
        };

        let mut type_decoder = decoder::Decoder::new(raw_metadata);
        let metadata = Metadata::deserialize(&mut type_decoder)?;

        let search_tree_size = (metadata.node_count as usize) * (metadata.record_size as usize) / 4;
        let decoder = BinaryDecoder {
            buf: metadata_decoder.buf,
            pointer_base: search_tree_size + data_section_separator_size,
        };

        let mut reader = Reader {
            decoder,
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
    pub fn lookup<T>(&self, address: IpAddr) -> Result<T, MaxMindDBError>
    where
        T: Deserialize<'de>,
    {
        self.lookup_prefix(address).map(|(v, _)| v)
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
    /// let ip: IpAddr = "89.160.20.128".parse().unwrap();
    /// let (city, prefix_len) = reader.lookup_prefix::<geoip2::City>(ip).unwrap();
    /// print!("{:?}, prefix length: {}", city, prefix_len);
    /// ```
    pub fn lookup_prefix<T>(&self, address: IpAddr) -> Result<(T, usize), MaxMindDBError>
    where
        T: Deserialize<'de>,
    {
        let ip_bytes = ip_to_bytes(address);
        let (pointer, prefix_len) = self.find_address_in_tree(&ip_bytes)?;
        if pointer == 0 {
            return Err(MaxMindDBError::AddressNotFoundError(
                "Address not found in database".to_owned(),
            ));
        }
        let rec = self.resolve_data_pointer(pointer)?;
        let mut decoder = decoder::Decoder::new(rec);

        T::deserialize(&mut decoder).map(|v| (v, prefix_len))
    }

    fn find_address_in_tree(&self, ip_address: &[u8]) -> Result<(usize, usize), MaxMindDBError> {
        let bit_count = ip_address.len() * 8;
        let mut node = self.start_node(bit_count)?;

        let node_count = self.metadata.node_count as usize;
        let mut prefix_len = bit_count;

        for i in 0..bit_count {
            if node >= node_count {
                prefix_len = i;
                break;
            }
            let bit = 1 & (ip_address[i >> 3] >> (7 - (i % 8)));

            node = self.read_node(node, bit as usize)?;
        }
        if node == node_count {
            Ok((0, prefix_len))
        } else if node > node_count {
            Ok((node, prefix_len))
        } else {
            Err(MaxMindDBError::InvalidDatabaseError(
                "invalid node in search tree".to_owned(),
            ))
        }
    }

    fn start_node(&self, length: usize) -> Result<usize, MaxMindDBError> {
        if length == 128 {
            Ok(0)
        } else {
            Ok(self.ipv4_start)
        }
    }

    fn find_ipv4_start(&self) -> Result<usize, MaxMindDBError> {
        if self.metadata.ip_version != 6 {
            return Ok(0);
        }

        // We are looking up an IPv4 address in an IPv6 tree. Skip over the
        // first 96 nodes.
        let mut node: usize = 0usize;
        for _ in 0u8..96 {
            if node >= self.metadata.node_count as usize {
                break;
            }
            node = self.read_node(node, 0)?;
        }
        Ok(node)
    }

    fn read_node(&self, node_number: usize, index: usize) -> Result<usize, MaxMindDBError> {
        let buf = self.decoder.buf.as_ref();
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

    fn resolve_data_pointer(&self, pointer: usize) -> Result<decoder::DataRecord, MaxMindDBError> {
        let search_tree_size =
            (self.metadata.record_size as usize) * (self.metadata.node_count as usize) / 4;

        let resolved = pointer - (self.metadata.node_count as usize) + search_tree_size;

        if resolved > self.decoder.buf.as_ref().len() {
            return Err(MaxMindDBError::InvalidDatabaseError(
                "the MaxMind DB file's search tree \
                 is corrupt"
                    .to_owned(),
            ));
        }

        let (record, _) = self.decoder.decode(resolved);
        record
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

fn find_metadata_start(buf: &[u8]) -> Result<usize, MaxMindDBError> {
    // This is reversed to make the loop below a bit simpler
    let metadata_start_marker: [u8; 14] = [
        0x6d, 0x6f, 0x63, 0x2e, 0x64, 0x6e, 0x69, 0x4d, 0x78, 0x61, 0x4d, 0xEF, 0xCD, 0xAB,
    ];
    let marker_length = metadata_start_marker.len();

    // XXX - ugly code
    for start_position in marker_length..buf.len() - 1 {
        let mut not_found = false;
        for (offset, marker_byte) in metadata_start_marker.iter().enumerate() {
            let file_byte = buf[buf.len() - start_position - offset - 1];
            if file_byte != *marker_byte {
                not_found = true;
                break;
            }
        }
        if !not_found {
            return Ok(buf.len() - start_position);
        }
    }
    Err(MaxMindDBError::InvalidDatabaseError(
        "Could not find MaxMind DB metadata in file.".to_owned(),
    ))
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
