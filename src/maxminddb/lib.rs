#![crate_name = "maxminddb"]
#![crate_type = "dylib"]
#![crate_type = "rlib"]

#![deny(trivial_casts, trivial_numeric_casts,
        unstable_features,
        unused_import_braces, unused_qualifications)]

#![cfg_attr(feature = "dev", allow(unstable_features))]
#![cfg_attr(feature = "dev", feature(plugin))]
#![cfg_attr(feature = "dev", plugin(clippy))]

#[macro_use]
extern crate log;

extern crate rustc_serialize;

use std::collections::BTreeMap;
use std::fs::File;
use std::io::prelude::*;
use std::io;
use std::error::Error;
use std::mem;
use std::net::SocketAddr;
use std::path::Path;

use rustc_serialize::Decodable;

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

type BinaryDecodeResult<T> = (Result<T, MaxMindDBError>, usize);

#[derive(Clone, Debug, PartialEq)]
pub enum DataRecord {
    String(String),
    Double(f64),
    Byte(u8),
    Uint16(u16),
    Uint32(u32),
    Map(Box<DbMap>),
    Int32(i32),
    Uint64(u64),
    Boolean(bool),
    Array(DbArray),
    Float(f32),
    Null,
}

pub type DbArray = Vec<DataRecord>;
pub type DbMap = BTreeMap<String, DataRecord>;

#[derive(RustcDecodable, Debug)]
pub struct Metadata {
    pub binary_format_major_version: u16,
    pub binary_format_minor_version: u16,
    pub build_epoch: u64,
    pub database_type: String,
    pub description: BTreeMap<String, String>,
    pub ip_version: u16,
    pub languages: Vec<String>,
    pub node_count: usize,
    pub record_size: u16,
}

struct BinaryDecoder {
    buf: Vec<u8>,
    pointer_base: usize,
}

impl BinaryDecoder {
    fn decode_array(&self, size: usize, offset: usize) -> BinaryDecodeResult<DataRecord> {
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
        (Ok(DataRecord::Array(array)), new_offset)
    }

    fn decode_bool(&self, size: usize, offset: usize) -> BinaryDecodeResult<DataRecord> {
        match size {
            0 | 1 => (Ok(DataRecord::Boolean(size != 0)), offset),
            s => (Err(MaxMindDBError::InvalidDatabaseError(format!("float of size {:?}", s))),
                  0),
        }
    }

    fn decode_bytes(&self, size: usize, offset: usize) -> BinaryDecodeResult<DataRecord> {
        let new_offset = offset + size;
        let u8_slice = &self.buf[offset..new_offset];

        let bytes = u8_slice.iter().map(|&b| DataRecord::Byte(b)).collect();

        (Ok(DataRecord::Array(bytes)), new_offset)
    }

    fn decode_float(&self, size: usize, offset: usize) -> BinaryDecodeResult<DataRecord> {
        match size {
            4 => {
                let new_offset = offset + size;

                let value = self.buf[offset..new_offset]
                                .iter()
                                .fold(0u32, |acc, &b| (acc << 8) | b as u32);
                let float_value: f32 = unsafe { mem::transmute(value) };
                (Ok(DataRecord::Float(float_value)), new_offset)
            }
            s => (Err(MaxMindDBError::InvalidDatabaseError(format!("float of size {:?}", s))),
                  0),
        }
    }

    fn decode_double(&self, size: usize, offset: usize) -> BinaryDecodeResult<DataRecord> {
        match size {
            8 => {
                let new_offset = offset + size;

                let value = self.buf[offset..new_offset]
                                .iter()
                                .fold(0u64, |acc, &b| (acc << 8) | b as u64);
                let float_value: f64 = unsafe { mem::transmute(value) };
                (Ok(DataRecord::Double(float_value)), new_offset)
            }
            s => (Err(MaxMindDBError::InvalidDatabaseError(format!("double of size {:?}", s))),
                  0),
        }
    }

    fn decode_uint64(&self, size: usize, offset: usize) -> BinaryDecodeResult<DataRecord> {
        match size {
            s if s <= 8 => {
                let new_offset = offset + size;

                let value = self.buf[offset..new_offset]
                                .iter()
                                .fold(0u64, |acc, &b| (acc << 8) | b as u64);
                (Ok(DataRecord::Uint64(value)), new_offset)
            }
            s => (Err(MaxMindDBError::InvalidDatabaseError(format!("u64 of size {:?}", s))),
                  0),
        }
    }

    fn decode_uint32(&self, size: usize, offset: usize) -> BinaryDecodeResult<DataRecord> {
        match size {
            s if s <= 4 => {
                match self.decode_uint64(size, offset) {
                    (Ok(DataRecord::Uint64(u)), o) => (Ok(DataRecord::Uint32(u as u32)), o),
                    e => e,
                }
            }
            s => (Err(MaxMindDBError::InvalidDatabaseError(format!("u32 of size {:?}", s))),
                  0),
        }
    }

    fn decode_uint16(&self, size: usize, offset: usize) -> BinaryDecodeResult<DataRecord> {
        match size {
            s if s <= 4 => {
                match self.decode_uint64(size, offset) {
                    (Ok(DataRecord::Uint64(u)), o) => (Ok(DataRecord::Uint16(u as u16)), o),
                    e => e,
                }
            }
            s => (Err(MaxMindDBError::InvalidDatabaseError(format!("u16 of size {:?}", s))),
                  0),
        }
    }

    fn decode_int(&self, size: usize, offset: usize) -> BinaryDecodeResult<DataRecord> {
        match size {
            s if s <= 4 => {
                let new_offset = offset + size;

                let value = self.buf[offset..new_offset]
                                .iter()
                                .fold(0i32, |acc, &b| (acc << 8) | b as i32);
                (Ok(DataRecord::Int32(value)), new_offset)
            }
            s => (Err(MaxMindDBError::InvalidDatabaseError(format!("int32 of size {:?}", s))),
                  0),
        }
    }

    fn decode_map(&self, size: usize, offset: usize) -> BinaryDecodeResult<DataRecord> {
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
                DataRecord::String(s) => s,
                v => return (Err(MaxMindDBError::InvalidDatabaseError(format!("unexpected map \
                                                                               key type {:?}",
                                                                              v))),
                             0),
            };
            values.insert(str_key, val);
        }
        (Ok(DataRecord::Map(values)), new_offset)
    }


    fn decode_pointer(&self, size: usize, offset: usize) -> BinaryDecodeResult<DataRecord> {
        let pointer_value_offset = [0, 0, 2048, 526336, 0];
        let pointer_size = ((size >> 3) & 0x3) + 1;
        let new_offset = offset + pointer_size;
        let pointer_bytes = &self.buf[offset..new_offset];

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

    fn decode_string(&self, size: usize, offset: usize) -> BinaryDecodeResult<DataRecord> {
        use std::str::from_utf8;

        let new_offset: usize = offset + size;
        let bytes = &self.buf[offset..new_offset];
        match from_utf8(bytes) {
            Ok(v) => (Ok(DataRecord::String(v.to_owned())), new_offset),
            Err(_) =>
                (Err(MaxMindDBError::InvalidDatabaseError("error decoding string".to_owned())),
                 new_offset),
        }
    }

    fn decode(&self, offset: usize) -> BinaryDecodeResult<DataRecord> {
        let mut new_offset = offset + 1;
        let ctrl_byte = self.buf[offset];

        let mut type_num = ctrl_byte >> 5;

        // Extended type
        if type_num == 0 {
            type_num = self.buf[new_offset] + 7;
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

        let bytes_to_read = if size > 28 {
            size - 28
        } else {
            0
        };

        let new_offset = offset + bytes_to_read;
        let size_bytes = &self.buf[offset..new_offset];

        size = match size {
            s if s < 29 => s,
            29 => 29usize + size_bytes[0] as usize,
            30 => {
                285usize + to_usize(0, size_bytes)
            }
            _ => {
                65821usize + to_usize(0, size_bytes)
            }
        };
        (size, new_offset)
    }

    fn decode_from_type(&self,
                        data_type: u8,
                        size: usize,
                        offset: usize)
                        -> BinaryDecodeResult<DataRecord> {
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
            u => (Err(MaxMindDBError::InvalidDatabaseError(format!("Unknown data type: {:?}", u))),
                  offset),
        }
    }
}


/// A reader for the MaxMind DB format
pub struct Reader {
    decoder: BinaryDecoder,
    pub metadata: Metadata,
    ipv4_start: usize,
}

impl Reader {

    /// Open a MaxMind DB database file.
    ///
    /// # Example
    ///
    /// ```
    /// let reader = maxminddb::Reader::open("test-data/test-data/GeoIP2-City-Test.mmdb").unwrap();
    /// ```
    pub fn open(database: &str) -> Result<Reader, MaxMindDBError> {
        let data_section_separator_size = 16;

        let path = Path::new(database);

        let mut f = try!(File::open(&path));

        let mut buf = Vec::new();
        try!(f.read_to_end(&mut buf));
        let metadata_start = try!(find_metadata_start(&buf));

        let metadata_decoder = BinaryDecoder {
            buf: buf,
            pointer_base: metadata_start,
        };

        let raw_metadata = match metadata_decoder.decode(metadata_start) {
            (Ok(m), _) => m,
            m => return Err(MaxMindDBError::InvalidDatabaseError(format!("metadata of wrong \
                                                                          type: {:?}",
                                                                         m))),
        };

        let mut type_decoder = decoder::Decoder::new(raw_metadata);
        let metadata: Metadata = try!(Decodable::decode(&mut type_decoder));

        let search_tree_size = metadata.node_count * (metadata.record_size as usize) / 4;
        let decoder = BinaryDecoder {
            buf: metadata_decoder.buf,
            pointer_base: search_tree_size + data_section_separator_size,
        };

        let mut reader = Reader {
            decoder: decoder,
            metadata: metadata,
            ipv4_start: 0,
        };
        reader.ipv4_start = try!(reader.find_ipv4_start());

        Ok(reader)
    }


    /// Lookup the socket address in the opened MaxMind DB
    ///
    /// Example:
    ///
    /// ```
    /// use maxminddb::geoip2;
    /// use std::net::SocketAddr;
    /// use std::str::FromStr;
    ///
    /// let reader = maxminddb::Reader::open("test-data/test-data/GeoIP2-City-Test.mmdb").unwrap();
    ///
    /// let ip: SocketAddr = FromStr::from_str("89.160.20.128:0").unwrap();
    /// let city: geoip2::City = reader.lookup(ip).unwrap();
    /// print!("{:?}", city);
    /// ```
    ///
    /// Note that SocketAddr requires a port, which is not needed to look up
    /// the address in the database. This library will likely switch to IpAddr
    /// if the feature gate for that is removed.
    pub fn lookup<T: Decodable>(&self, address: SocketAddr) -> Result<T, MaxMindDBError> {
        let ip_bytes = ip_to_bytes(address);
        let pointer = try!(self.find_address_in_tree(ip_bytes));
        if pointer <= 0 {
            return Err(MaxMindDBError::AddressNotFoundError("Address not found in database"
                                                                .to_owned()));
        }
        let rec = try!(self.resolve_data_pointer(pointer));
        let mut decoder = decoder::Decoder::new(rec);
        Decodable::decode(&mut decoder)
    }

    fn find_address_in_tree(&self, ip_address: Vec<u8>) -> Result<usize, MaxMindDBError> {
        let bit_count = ip_address.len() * 8;
        let mut node = try!(self.start_node(bit_count));

        for i in 0..bit_count {
            if node >= self.metadata.node_count {
                break;
            }
            let bit = 1 & (ip_address[i >> 3] >> (7 - (i % 8)));

            node = try!(self.read_node(node, bit as usize));
        }
        if node == self.metadata.node_count {
            Ok(0)
        } else if node > self.metadata.node_count {
            Ok(node)
        } else {
            Err(MaxMindDBError::InvalidDatabaseError("invalid node in search tree".to_owned()))
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
            if node >= self.metadata.node_count {
                break;
            }
            node = try!(self.read_node(node, 0));
        }
        Ok(node)
    }


    fn read_node(&self, node_number: usize, index: usize) -> Result<usize, MaxMindDBError> {

        let base_offset = node_number * (self.metadata.record_size as usize) / 4;

        let val = match self.metadata.record_size {
            24 => {
                let offset = base_offset + index * 3;
                to_usize(0, &self.decoder.buf[offset..offset + 3])
            }
            28 => {
                let mut middle = self.decoder.buf[base_offset + 3];
                if index != 0 {
                    middle &= 0x0F
                } else {
                    middle = (0xF0 & middle) >> 4
                }
                let offset = base_offset + index * 4;
                to_usize(middle, &self.decoder.buf[offset..offset + 3])
            }
            32 => {
                let offset = base_offset + index * 4;
                to_usize(0, &self.decoder.buf[offset..offset + 4])
            }
            s => return Err(MaxMindDBError::InvalidDatabaseError(format!("unknown record size: \
                                                                          {:?}",
                                                                         s))),
        };
        Ok(val)
    }

    fn resolve_data_pointer(&self, pointer: usize) -> Result<DataRecord, MaxMindDBError> {
        let search_tree_size = (self.metadata.record_size as usize) * self.metadata.node_count / 4;

        let resolved = pointer - self.metadata.node_count + search_tree_size;

        if resolved > self.decoder.buf.len() {
            return Err(MaxMindDBError::InvalidDatabaseError("the MaxMind DB file's search tree \
                                                             is corrupt"
                                                                .to_owned()));
        }

        let (record, _) = self.decoder.decode(resolved);
        record
    }
}

// I haven't moved all patterns of this form to a generic function as
// the FromPrimitive trait is unstable
fn to_usize(base: u8, bytes: &[u8]) -> usize {
    bytes.iter().fold(base as usize, |acc, &b| (acc << 8) | b as usize)
}

fn ip_to_bytes(address: SocketAddr) -> Vec<u8> {
    match address {
        // I am sure there is a less horrible way to do this.
        SocketAddr::V4(a) => a.ip().octets().iter().map(|&x| x).collect(),
        SocketAddr::V6(a) => {
            let s = a.ip().segments();
            vec![(s[0] >> 8) as u8,
                 s[0] as u8,
                 (s[1] >> 8) as u8,
                 s[1] as u8,
                 (s[2] >> 8) as u8,
                 s[2] as u8,
                 (s[3] >> 8) as u8,
                 s[3] as u8,
                 (s[4] >> 8) as u8,
                 s[4] as u8,
                 (s[5] >> 8) as u8,
                 s[5] as u8,
                 (s[6] >> 8) as u8,
                 s[6] as u8,
                 (s[7] >> 8) as u8,
                 s[7] as u8]
        }
    }
}


fn find_metadata_start(buf: &[u8]) -> Result<usize, MaxMindDBError> {
    // This is reversed to make the loop below a bit simpler
    let metadata_start_marker: [u8; 14] = [0x6d, 0x6f, 0x63, 0x2e, 0x64, 0x6e, 0x69, 0x4d, 0x78,
                                           0x61, 0x4d, 0xEF, 0xCD, 0xAB];
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
    Err(MaxMindDBError::InvalidDatabaseError("Could not find MaxMind DB metadata in file."
                                                 .to_owned()))
}

mod decoder;
pub mod geoip2;

#[cfg(test)]
mod reader_test;
