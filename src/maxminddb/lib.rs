#![crate_name = "maxminddb"]
#![crate_type = "dylib"]
#![crate_type = "rlib"]

#![feature(collections)]
#![feature(core)]
#![feature(libc)]
#![feature(old_io)]
#![feature(old_path)]
#![feature(os)]
#![feature(std_misc)]

#[macro_use] extern crate log;

extern crate collections;
extern crate core;
extern crate libc;
extern crate "rustc-serialize" as rustc_serialize;

use core::fmt::Debug;
use std::collections::BTreeMap;
use std::fmt;
use std::old_io::BufReader;
use std::old_io::File;
use std::old_io::net::ip::{IpAddr,Ipv6Addr,Ipv4Addr};
use std::old_io::{Open, Read};
use std::os;
use std::string;
use std::os::unix::{AsRawFd};

use rustc_serialize::Decodable;

pub use self::decoder::Decoder;

#[derive(Debug, PartialEq)]
pub enum Error {
    AddressNotFoundError(string::String),
    InvalidDatabaseError(string::String),
    IoError(string::String),
    MapError(string::String),
    DecodingError(string::String),
}

pub type BinaryDecodeResult<T> = (Result<T, Error>, usize);

#[derive(Clone, PartialEq)]
pub enum DataRecord {
    String(string::String),
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
pub type DbMap = BTreeMap<string::String, DataRecord>;

impl fmt::Debug for DataRecord {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
      match self {
        &DataRecord::String(ref v) => v.fmt(f),
        &DataRecord::Double(v) => v.fmt(f),
        &DataRecord::Byte(v) => v.fmt(f),
        &DataRecord::Uint16(v) => v.fmt(f),
        &DataRecord::Uint32(v) => v.fmt(f),
        &DataRecord::Uint64(v) => v.fmt(f),
        &DataRecord::Map(ref v) => v.fmt(f),
        &DataRecord::Int32(v) => v.fmt(f),
        &DataRecord::Boolean(v) => v.fmt(f),
        &DataRecord::Array(ref v) => v.fmt(f),
        &DataRecord::Float(v) => v.fmt(f),
        &DataRecord::Null => "Null".fmt(f),
      }
    }
}


#[derive(RustcDecodable)]
pub struct Metadata {
    pub binary_format_major_version : u16,
    pub binary_format_minor_version : u16,
    pub build_epoch                 : u64,
    pub database_type               : string::String,
    pub description                 : BTreeMap<string::String, string::String>,
    pub ip_version                  : u16,
    pub languages                   : Vec<string::String>,
    pub node_count                  : usize,
    pub record_size                 : u16,
}

struct BinaryDecoder {
    map      : os::MemoryMap,
    pointer_base: usize
}

impl BinaryDecoder {
    fn decode_array(&self, size: usize, offset: usize) -> BinaryDecodeResult<DataRecord> {
        let mut array = Vec::new();
        let mut new_offset = offset;

        for _ in range(0, size) {
            let (val, tmp_offset) = match self.decode(new_offset) {
                (Ok(v), os) => (v, os),
                (Err(e), os) => return (Err(e), os)
            };
            new_offset = tmp_offset;
            array.push(val);
        }
        (Ok(DataRecord::Array(array)), new_offset)
    }

    fn decode_bool(&self, size: usize, offset: usize) -> BinaryDecodeResult<DataRecord> {
        match size {
            0|1 => (Ok(DataRecord::Boolean(size != 0)), offset),
             s => (Err(Error::InvalidDatabaseError(format!("float of size {:?}", s))), 0)
         }
    }

    fn decode_bytes(&self, size: usize, offset: usize) -> BinaryDecodeResult<DataRecord> {
        let new_offset = offset + size;
        let u8_slice = read_from_map(&self.map, size, offset);
        // XXX - baby rust
        let mut bytes = Vec::new();
        for b in u8_slice.into_iter() {
            bytes.push(DataRecord::Byte(b));
        }
        (Ok(DataRecord::Array(bytes)), new_offset)
    }

    fn decode_float(&self, size: usize, offset: usize) -> BinaryDecodeResult<DataRecord> {
        match size {
            4 => {
                let new_offset = offset + size;

                let buf = read_from_map(&self.map, size, offset);
                let mut reader = BufReader::new(buf.as_slice());
                (Ok(DataRecord::Float(reader.read_be_f32().unwrap())), new_offset)
            },
            s => (Err(Error::InvalidDatabaseError(format!("float of size {:?}", s))), 0)
        }
    }

    fn decode_double(&self, size: usize, offset: usize) -> BinaryDecodeResult<DataRecord> {
        match size {
            8 => {
                let new_offset = offset + size;

                let buf = read_from_map(&self.map, size, offset);
                let mut reader = BufReader::new(buf.as_slice());
                (Ok(DataRecord::Double(reader.read_be_f64().unwrap())), new_offset)
            },
            s => (Err(Error::InvalidDatabaseError(format!("double of size {:?}", s))), 0)
        }
    }

    fn decode_uint64(&self, size: usize, offset: usize) -> BinaryDecodeResult<DataRecord> {
        match size {
            s if s <= 8 => {
                let new_offset = offset + size;

                let value = if size == 0 {
                        0
                    } else {
                        let buf = read_from_map(&self.map, size, offset);
                        let mut reader = BufReader::new(buf.as_slice());
                        reader.read_be_uint_n(size).unwrap()
                    };
                (Ok(DataRecord::Uint64(value)), new_offset)
            },
            s => (Err(Error::InvalidDatabaseError(format!("u64 of size {:?}", s))), 0)
        }
    }

    fn decode_uint32(&self, size: usize, offset: usize) -> BinaryDecodeResult<DataRecord> {
        match size {
            s if s <= 4 => {
                match self.decode_uint64(size, offset) {
                    (Ok(DataRecord::Uint64(u)), o) => (Ok(DataRecord::Uint32(u as u32)), o),
                    e => e
                }
            },
            s => (Err(Error::InvalidDatabaseError(format!("u32 of size {:?}", s))), 0)
        }
    }

    fn decode_uint16(&self, size: usize, offset: usize) -> BinaryDecodeResult<DataRecord> {
        match size {
            s if s <= 4 => {
                match self.decode_uint64(size, offset) {
                    (Ok(DataRecord::Uint64(u)), o) => (Ok(DataRecord::Uint16(u as u16)), o),
                    e => e
                }
            },
            s => (Err(Error::InvalidDatabaseError(format!("u16 of size {:?}", s))), 0)
        }
    }

    fn decode_int(&self, size: usize, offset: usize) -> BinaryDecodeResult<DataRecord> {
        match size {
            s if s <= 4 => {
                let new_offset = offset + size;

                let buf = read_from_map(&self.map, size, offset);
                let mut reader = BufReader::new(buf.as_slice());
                (Ok(DataRecord::Int32(reader.read_be_int_n(size).unwrap() as i32)), new_offset)
            },
            s => (Err(Error::InvalidDatabaseError(format!("int32 of size {:?}", s))), 0)
        }
    }

    fn decode_map(&self, size: usize, offset: usize) -> BinaryDecodeResult<DataRecord> {
        let mut values = Box::new(BTreeMap::new());
        let mut new_offset = offset;

        for _ in range(0, size) {
            let (key, val_offset) = match self.decode(new_offset) {
                (Ok(v), os) => (v, os),
                (Err(e), os) => return (Err(e), os)
            };
            let (val, tmp_offset) = match self.decode(val_offset) {
                (Ok(v), os) => (v, os),
                (Err(e), os) => return (Err(e), os)
            };
            new_offset = tmp_offset;

            let str_key = match key {
                DataRecord::String(s) => s,
                v => return (Err(Error::InvalidDatabaseError(format!("unexpected map key type {:?}", v))), 0)
            };
            values.insert(str_key, val);
        }
        (Ok(DataRecord::Map(values)), new_offset)
    }


    fn decode_pointer(&self, size: usize, offset: usize) -> BinaryDecodeResult<DataRecord> {
        let pointer_value_offset = [0, 0, 2048, 526336, 0];
        let pointer_size = ((size >> 3) & 0x3) + 1;
        let new_offset = offset + pointer_size;
        let pointer_bytes = read_from_map(&self.map, pointer_size, offset);

        let packed = if pointer_size == 4 {
                pointer_bytes
            } else {
                // XXX - make this sane.
                [vec![ (size & 0x7) as u8 ], pointer_bytes].concat()
            };
        let mut r = BufReader::new(packed.as_slice());
        let unpacked = r.read_be_uint_n(packed.len()).unwrap() as usize;
        let pointer = unpacked + self.pointer_base + pointer_value_offset[pointer_size];

        // XXX fix cast. Use usize everywhere?
        let (result, _) = self.decode(pointer as usize);
        (result, new_offset)
    }

    fn decode_string(&self, size: usize, offset: usize) -> BinaryDecodeResult<DataRecord> {
        use std::str::from_utf8;

        let new_offset : usize = offset + size;
        let bytes = read_from_map(&self.map, size, offset);
        match from_utf8(bytes.as_slice()) {
            Ok(v) => (Ok(DataRecord::String(v.to_string())), new_offset),
            Err(_) => (Err(Error::InvalidDatabaseError("error decoding string".to_string())), new_offset)
        }
    }

    fn decode(&self, offset: usize) -> BinaryDecodeResult<DataRecord> {
        let mut new_offset = offset + 1;
        let ctrl_byte = read_u8_from_map(&self.map, offset);

        let mut type_num = ctrl_byte >> 5;

        // Extended type
        if type_num == 0 {
            type_num = read_u8_from_map(&self.map, new_offset) + 7;
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
        let size_bytes = read_from_map(&self.map, bytes_to_read, offset);

        size = match size {
                s if s < 29 => s,
                29 => 29usize + size_bytes[0] as usize,
                30 => {
                    let mut r = BufReader::new(size_bytes.as_slice());
                    285usize + r.read_be_uint_n(size_bytes.len()).unwrap() as usize
                },
                _ => {
                    let mut r = BufReader::new(size_bytes.as_slice());
                    65821usize + r.read_be_uint_n(size_bytes.len()).unwrap() as usize
                }
            };
        (size, new_offset)
    }

    fn decode_from_type(&self, data_type: u8, size: usize, offset: usize) -> BinaryDecodeResult<DataRecord> {
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
            u  => (Err(Error::InvalidDatabaseError(format!("Unknown data type: {:?}", u))), offset),
        }
    }
}

pub struct Reader {
    decoder: BinaryDecoder,
    pub metadata: Metadata,
    ipv4_start: usize,
}

impl Reader {

    pub fn open(database: &str) -> Result<Reader, Error> {
        let data_section_separator_size = 16;

        let path = Path::new(database);

        let f = match File::open_mode(&path, Open, Read) {
            Ok(f)  => f,
            Err(_) => return Err(Error::IoError("Error opening file".to_string()))
        };
        let fd = f.as_raw_fd();

        let stats = match f.stat() {
            Ok(s) => s,
            Err(_) => return Err(Error::IoError("Error calling stat on file".to_string()))
        };

        let database_size = stats.size as usize;
        let map = match os::MemoryMap::new(database_size, &[os::MapOption::MapReadable, os::MapOption::MapFd(fd), os::MapOption::   MapOffset(0)])
        {
            Ok(mem)  => mem,
            Err(msg) => return Err(Error::MapError(format!("{:?}", msg)))
        };

        let metadata_start = match find_metadata_start(&map) {
            Ok(i) => i,
            Err(e) => return Err(e)
        };
        let metadata_decoder = BinaryDecoder { map: map, pointer_base: metadata_start};

        let raw_metadata = match metadata_decoder.decode(metadata_start) {
            (Ok(m), _) => m,
            m      => return Err(Error::InvalidDatabaseError(format!("metadata of wrong type: {:?}", m))),
        };

        let mut type_decoder = ::Decoder::new(raw_metadata);
        let metadata: Metadata = match Decodable::decode(&mut type_decoder) {
            Ok(v) => v,
            Err(e) => return Err(Error::InvalidDatabaseError(format!("Decoding error: {:?}", e)))
        };

        let search_tree_size = metadata.node_count * (metadata.record_size as usize) / 4;
        let decoder = BinaryDecoder{map: metadata_decoder.map, pointer_base: search_tree_size as usize + data_section_separator_size};

        let mut reader = Reader { decoder: decoder, metadata: metadata, ipv4_start: 0, };
        match reader.find_ipv4_start() {
            Ok(i) => reader.ipv4_start = i,
            Err(e) => return Err(e)
        };

        Ok(reader)
    }


    pub fn lookup(&self, ip_address: IpAddr) -> Result<DataRecord, Error> {
    //  if len(ipAddress) == 16 && r.Metadata.IPVersion == 4 {
    //      return nil, fmt.Errorf("error looking up '%s': you attempted to look up an IPv6 address in an IPv4-only database", ipAddress.String())
    //  }
        let ip_bytes = ip_to_bytes(ip_address);
        let pointer = match self.find_address_in_tree(ip_bytes) {
            Ok(v) => v,
            Err(e) => return Err(e)
        };
        if pointer > 0 {
            self.resolve_data_pointer(pointer)
        } else {
            Err(Error::AddressNotFoundError("Address not found in database".to_string()))
        }
    }

    fn find_address_in_tree(&self, ip_address: Vec<u8>) -> Result<usize, Error> {
        let bit_count = ip_address.len()*8;
        let mut node = try!(self.start_node(bit_count));

        for i in range(0, bit_count) {
            if node >= self.metadata.node_count {
                break;
            }
            let bit = 1 & (ip_address[i>>3] >> (7-(i % 8)));

            node = match self.read_node(node, bit as usize) {
                Ok(v) => v,
                e => return e
            };
        }
        if node == self.metadata.node_count {
            Ok(0)
        } else if node > self.metadata.node_count {
            Ok(node)
        } else {
           Err(Error::InvalidDatabaseError("invalid node in search tree".to_string()))
        }
    }

    fn start_node(&self, length: usize) -> Result<usize, Error> {
        if length == 128 {
            Ok(0)
        } else {
            Ok(self.ipv4_start)
        }
    }

    fn find_ipv4_start(&self)  -> Result<usize, Error> {

        if self.metadata.ip_version != 6 {
            return Ok(0);
        }

        // We are looking up an IPv4 address in an IPv6 tree. Skip over the
        // first 96 nodes.
        let mut node: usize = 0usize;
        for _ in range(0u8, 96) {
            if node >= self.metadata.node_count {
                break;
            }
            node = match self.read_node(node, 0) {
                Ok(v) => v,
                e => return e
            };
        }
        Ok(node)
    }


    fn read_node(&self, node_number: usize, index: usize) -> Result<usize, Error> {

        let base_offset = node_number * (self.metadata.record_size as usize)/ 4;

        let bytes = match self.metadata.record_size {
            24 => {
                let offset = base_offset + index * 3;
                read_from_map(&self.decoder.map, 3, offset)
            },
            28 => {
                let mut middle = read_u8_from_map(&self.decoder.map, base_offset + 3);
                if index != 0 {
                    middle &= 0x0F
                } else {
                    middle = (0xF0 & middle) >> 4
                }
                let offset = base_offset + index * 4;
                [vec![middle], read_from_map(&self.decoder.map, 3, offset)].concat()
            },
            32 => {
                let offset = base_offset + index * 4;
                read_from_map(&self.decoder.map, 4, offset)
            },
            s => return Err(Error::InvalidDatabaseError(format!("unknown record size: {:?}", s)))
        };
        let mut reader = BufReader::new(bytes.as_slice());
        Ok(reader.read_be_uint_n(bytes.len()).unwrap() as usize)
    }

    fn resolve_data_pointer(&self, pointer: usize) -> Result<DataRecord, Error> {
        let search_tree_size = (self.metadata.record_size as usize) * self.metadata.node_count / 4;

        let resolved = pointer - self.metadata.node_count + search_tree_size;

        if resolved > self.decoder.map.len()  {
            return Err(Error::InvalidDatabaseError("the MaxMind DB file's search tree is corrupt".to_string()));
        }

        let (record, _) = self.decoder.decode(resolved);
        record
    }
}

fn read_u8_from_map(map: &os::MemoryMap, offset: usize) -> u8 {
    match read_from_map(map, 1, offset).as_slice() {
        [head] => head,
        _ => unreachable!()
    }
}

fn read_from_map(map: &os::MemoryMap, size: usize, offset: usize) -> Vec<u8> {
    if offset >= map.len() - size {
        use std::intrinsics;
        error!("attempt to read beyond end of memory map: {:?}\n", offset);
        unsafe { intrinsics::abort() }
    }
    unsafe { Vec::from_raw_buf(map.data().offset(offset as isize) as *const u8, size)}
}

fn ip_to_bytes(ip_address: IpAddr) -> Vec<u8> {
    match ip_address {
        Ipv4Addr(a, b, c, d) => vec![a, b, c, d],
        // Ipv4 Compatible address
        Ipv6Addr(0, 0, 0, 0, 0, 0 , g, h) |
        Ipv6Addr(0, 0, 0, 0, 0, 0xFFFF , g, h) => vec![
                                            (g >> 8) as u8, g as u8,
                                            (h >> 8) as u8, h as u8
                                         ],
        Ipv6Addr(a, b, c, d, e, f, g, h) => vec![
                                            (a >> 8) as u8, a as u8,
                                            (b >> 8) as u8, b as u8,
                                            (c >> 8) as u8, c as u8,
                                            (d >> 8) as u8, d as u8,
                                            (e >> 8) as u8, e as u8,
                                            (f >> 8) as u8, f as u8,
                                            (g >> 8) as u8, g as u8,
                                            (h >> 8) as u8, h as u8
                                         ],
    }
}

fn find_metadata_start(map: &os::MemoryMap) -> Result<usize, Error> {
    // This is reversed to make the loop below a bit simpler
    let metadata_start_marker : [u8; 14] = [ 0x6d, 0x6f, 0x63, 0x2e, 0x64,
                                               0x6e, 0x69, 0x4d, 0x78, 0x61,
                                               0x4d, 0xEF, 0xCD, 0xAB,
                                             ];
    let marker_length = metadata_start_marker.len();

    // XXX - ugly code
    for start_position in range(marker_length, map.len() - 1) {
        let mut not_found = false;
        for (offset, marker_byte) in metadata_start_marker.iter().enumerate() {
            let file_byte = read_from_map(map, 1,
                    (map.len() - start_position - offset - 1 )
                    );
            if file_byte[0] != *marker_byte {
                not_found = true;
                break;
            }
        }
        if !not_found {
            return Ok(map.len() - start_position);
        }
    }
    Err(Error::InvalidDatabaseError("Could not find MaxMind DB metadata in file.".to_string()))
}

mod decoder;

#[cfg(test)]
mod reader_test;

