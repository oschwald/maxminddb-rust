
#![feature(macro_rules)]

#![feature(phase)]
#[phase(syntax, link)] extern crate log;

extern crate collections;
extern crate native;

use std::fmt;
use std::io::BufReader;
use std::io::{Open, Read};
use std::io::net::ip::{IpAddr,Ipv6Addr,Ipv4Addr};
use std::from_str::FromStr;
use std::os;
use std::str;

use collections::TreeMap;


#[deriving(Eq, Show)]
pub enum Error {
    InvalidDatabaseError(~str),
}

pub type DecodeResult<T> = (Result<T, Error>, uint);

#[deriving(Clone, Eq)]
pub enum DataRecord {
    String(~str),
    Double(f64),
    Bytes(~[u8]),
    Uint16(u16),
    Uint32(u32),
    Map(~Map),
    Int32(i32),
    Uint64(u64),
    Uint128(Uint128),
    Boolean(bool),
    Array(Array),
    Float(f32),
}

pub type Array = ~[DataRecord];
pub type Map = TreeMap<~str, DataRecord>;
pub type Uint128 = (u64, u64);

impl fmt::Show for DataRecord {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
      match self {
        &String(ref v) => v.fmt(f),
        &Double(v) => v.fmt(f),
        &Bytes(ref v) => v.fmt(f),
        &Uint16(v) => v.fmt(f),
        &Uint32(v) => v.fmt(f),
        &Uint64(v) => v.fmt(f),
        &Map(ref v) => v.fmt(f),
        &Int32(v) => v.fmt(f),
        &Uint128(v) => v.fmt(f),
        &Boolean(v) => v.fmt(f),
        &Array(ref v) => v.fmt(f),
        &Float(v) => v.fmt(f),
      }
    }
}

// shamelessly taken from rust_js
impl fmt::Show for TreeMap<~str, DataRecord> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        try!(f.buf.write_str("{ "));
        match self.iter().last() {
            Some((last_key, _)) => {
                for (k, v) in self.iter() {
                    try!(write!(f.buf, "{}: {}", k, v));
                    if k != last_key {
                        try!(f.buf.write_str(", "));
                    }
                }
            },
            None => ()
        }
        f.buf.write_str("}")
    }
}

struct BinaryDecoder {
    map      : os::MemoryMap,
    pointer_base: uint
}


impl BinaryDecoder {
    fn decode_array(&self, size: uint, offset: uint) -> DecodeResult<DataRecord> {
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
        (Ok(Array(array.move_iter().collect())), new_offset)
    }

    fn decode_bool(&self, size: uint, offset: uint) -> DecodeResult<DataRecord> {
        (Ok(Boolean(size != 0)), offset)
    }

    fn decode_bytes(&self, size: uint, offset: uint) -> DecodeResult<DataRecord> {
        let new_offset = offset + size;
        let bytes = self.read_from_file(size, offset);
        (Ok(Bytes(bytes)), new_offset)
    }

    fn decode_float(&self, size: uint, offset: uint) -> DecodeResult<DataRecord> {
        let new_offset = offset + size;

        let buf = self.read_from_file(size, offset);
        let mut reader = BufReader::new(buf);
        (Ok(Float(reader.read_be_f32().unwrap())), new_offset)
    }

    fn decode_double(&self, size: uint, offset: uint) -> DecodeResult<DataRecord> {
        let new_offset = offset + size;

        let buf = self.read_from_file(size, offset);
        let mut reader = BufReader::new(buf);
        (Ok(Double(reader.read_be_f64().unwrap())), new_offset)
    }


    fn decode_uint(&self, size: uint, offset: uint) -> DecodeResult<DataRecord> {
        let new_offset = offset + size;

        let value = if size == 0 {
                0
            } else {
                let buf = self.read_from_file(size, offset);
                let mut reader = BufReader::new(buf);
                reader.read_be_uint_n(size).unwrap()
            };

        (Ok(Uint64(value)), new_offset)
    }

    fn decode_int(&self, size: uint, offset: uint) -> DecodeResult<DataRecord> {
        let new_offset = offset + size;

        let buf = self.read_from_file(size, offset);
        let mut reader = BufReader::new(buf);
        (Ok(Int32(reader.read_be_int_n(size).unwrap() as i32)), new_offset)
    }

    fn decode_map(&self, size: uint, offset: uint) -> DecodeResult<DataRecord> {
        let mut values = ~TreeMap::new();
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
                String(s) => s,
                v => fail!("unexpected map key type {}", v)
            };
            values.insert(str_key, val);
        }
        (Ok(Map(values)), new_offset)
    }


    fn decode_pointer(&self, size: uint, offset: uint) -> DecodeResult<DataRecord> {
        let pointer_value_offset = [0, 0, 2048, 526336, 0];
        let pointer_size = ((size >> 3) & 0x3) + 1;
        let new_offset = offset + pointer_size;
        let pointer_bytes = self.read_from_file(pointer_size, offset);

        let packed = if pointer_size == 4 {
                pointer_bytes
            } else {
                [ (size & 0x7) as u8 ] + pointer_bytes
            };
        let mut r = BufReader::new(packed);
        let unpacked = r.read_be_uint_n(packed.len()).unwrap() as uint;
        let pointer = unpacked + self.pointer_base + pointer_value_offset[pointer_size];

        // XXX fix cast. Use uint everywhere?
        let (result, _) = self.decode(pointer as uint);
        (result, new_offset)
    }

    fn decode_string(&self, size: uint, offset: uint) -> DecodeResult<DataRecord> {
        let new_offset : uint = offset + size;
        let bytes = self.read_from_file(size, offset);
        match str::from_utf8(bytes) {
            Some(v) => (Ok(String(v.to_str())), new_offset),
            None => fail!("error decoding string")//(Err(error!("error decoding string")), new_offset)
        }
    }

    fn decode(&self, offset: uint) -> DecodeResult<DataRecord> {
        let mut new_offset = offset + 1;
        let ctrl_byte = (self.read_from_file(1, offset))[0];

        let mut type_num = ctrl_byte >> 5;

        // Extended type
        if type_num == 0 {
            type_num = self.read_from_file(1, new_offset)[0] + 7;
            new_offset += 1;
        }

        let (size, value_offset) = self.size_from_ctrl_byte(ctrl_byte, new_offset, type_num);
        self.decode_from_type(type_num, size, value_offset)
    }

    fn size_from_ctrl_byte(&self, ctrl_byte: u8, offset: uint, type_num: u8) -> (uint, uint) {

        let mut size = (ctrl_byte & 0x1f) as uint;
        // extended
        if type_num == 0 {
            return (size, offset);
        }

        let bytes_to_read = if size > 28 { size - 28 } else { 0 };

        let new_offset = offset + bytes_to_read;
        let size_bytes = self.read_from_file(bytes_to_read, offset);

        size = match size {
                s if s < 29 => s,
                29 => 29u + size_bytes[0] as uint,
                30 => {
                    let mut r = BufReader::new(size_bytes);
                    285u + r.read_be_uint_n(size_bytes.len()).unwrap() as uint
                },
                _ => {
                    let mut r = BufReader::new(size_bytes);
                    65821u + r.read_be_uint_n(size_bytes.len()).unwrap() as uint
                }
            };
        (size, new_offset)
    }

    fn decode_from_type(&self, data_type: u8, size: uint, offset: uint) -> DecodeResult<DataRecord> {
        match data_type {
            1 => self.decode_pointer(size, offset),
            2 => self.decode_string(size, offset),
            3 => self.decode_double(size, offset),
            4 => self.decode_bytes(size, offset),
            5 => self.decode_uint(size, offset),
            6 => self.decode_uint(size, offset),
            7 => self.decode_map(size, offset),
            8 => self.decode_int(size, offset),
            9 => self.decode_uint(size, offset),
            10 => fail!("128 bit uint support is not implemented"),
            11 => self.decode_array(size, offset),
            14 => self.decode_bool(size, offset),
            15 => self.decode_float(size, offset),
            u  => fail!("Unknown data type: {}", u)
        }
    }

    fn read_from_file(&self, size: uint, offset: uint) -> ~[u8] {
        unsafe { std::slice::from_buf(self.map.data.offset(offset as int) as *u8, size)}
    }
}

macro_rules! expect(
    ($e:expr, Null) => ({
        match $e {
            Null => Ok(()),
            other => Err(ExpectedError("Null".to_owned(), format!("{}", other)))
        }
    });
    ($e:expr, $t:ident) => ({
        match $e {
            $t(v) => Ok(v),
            other => Err(ExpectedError(stringify!($t).to_owned(), format!("{}", other)))
        }
    })
)

// pub struct Decoder {
//     stack: Vec<DataRecord>,
// }

// ... decoder similar to the Json decoder

struct Reader {
    decoder: BinaryDecoder,
    metadata: ~TreeMap<~str, DataRecord>,
    ipv4_start: uint,
}

impl Reader {

    fn open(database: &str) -> Reader {
        let data_section_separator_size = 16;

        let f = match native::io::file::open(&database.to_c_str(),
                                             Open, Read) {
            Ok(f)  => f,
            Err(e) => fail!("Failed to open file: {}", e)
        };
        let fd = f.fd();

        let stats = match native::io::file::stat(&database.to_c_str()) {
            Ok(s) => s,
            Err(e) => fail!("Failed to stat file: {}", e)
        };

        let database_size = stats.size as uint;
        let m = match os::MemoryMap::new(database_size, [os::MapReadable, os::MapFd(fd), os::MapOffset(0)])
        {
            Ok(mem)  => mem,
            Err(msg) => fail!(msg.to_str())
        };

        let metadata_start = find_metadata_start(&m);
        let metadata_decoder = BinaryDecoder { map: m, pointer_base: metadata_start};

        // XXX -  eventually decode to struct
        let metadata = match metadata_decoder.decode(metadata_start) {
            (Ok(Map(m)), _) => m,
            m      => fail!("metadata of wrong type: {}", m),
        };

        let node_count = match metadata.find(&~"node_count").unwrap() {
            &Uint64(i) => i,
            _ => fail!("unexpected type")
        };

        let record_size = match metadata.find(&~"record_size").unwrap() {
            &Uint64(i) => i,
            _ => fail!("unexpected type")
        };

        let search_tree_size = node_count * record_size / 4;
        let decoder = BinaryDecoder{map: metadata_decoder.map, pointer_base: search_tree_size as uint + data_section_separator_size};

        // XXX - This should really be a Result given that it can fail
        Reader { decoder: decoder, metadata: metadata, ipv4_start: 0, }
    }


    fn lookup(&mut self, ip_address: IpAddr) -> Result<DataRecord, Error> {
    //  if len(ipAddress) == 16 && r.Metadata.IPVersion == 4 {
    //      return nil, fmt.Errorf("error looking up '%s': you attempted to look up an IPv6 address in an IPv4-only database", ipAddress.String())
    //  }
        let ip_bytes = ip_to_bytes(ip_address);
        let pointer = match self.find_address_in_tree(ip_bytes) {
            Ok(v) => v,
            Err(e) => return Err(e)
        };
        self.resolve_data_pointer(pointer)
    }

    fn find_address_in_tree(&mut self, ip_address: ~[u8]) -> Result<uint, Error> {
        let bit_count = ip_address.len()*8;
        let mut node = self.start_node(bit_count).unwrap();

        let node_count = match self.metadata.find(&~"node_count").unwrap() {
            &Uint64(i) => i as uint,
            _ => fail!("unexpected type")
        };

        for i in range(0, bit_count) {
            if node >= node_count {
                break;
            }
            let bit = 1 & (ip_address[i>>3] >> (7-(i % 8)));

            node = match self.read_node(node, bit as uint) {
                Ok(v) => v,
                e => return e
            };
        }
        if node == node_count {
            Ok(0)
        } else if node > node_count {
            Ok(node)
        } else {
           fail!("invalid node in search tree")
        }
    }

    fn start_node(&mut self, length: uint) -> Result<uint, Error> {
        let ip_version = match self.metadata.find(&~"ip_version").unwrap() {
            &Uint64(i) => i,
            _ => fail!("unexpected type")
        };
        if ip_version != 6 || length == 128 {
            return Ok(0);
        }

        // We are looking up an IPv4 address in an IPv6 tree. Skip over the
        // first 96 nodes.
        if self.ipv4_start != 0 {
            return Ok(self.ipv4_start);
        }

        let node_count = match self.metadata.find(&~"node_count").unwrap() {
            &Uint64(i) => i as uint,
            _ => fail!("unexpected type")
        };

        let mut node: uint = 0u;
        for _ in range(0, 96) {
            if node >= node_count {
                break;
            }
            node = match self.read_node(node, 0) {
                Ok(v) => v,
                e => return e
            };
        }
        self.ipv4_start = node;
        Ok(node)
    }


    fn read_node(&self, node_number: uint, index: uint) -> Result<uint, Error> {
        let record_size = match self.metadata.find(&~"record_size").unwrap() {
            &Uint64(i) => i as uint,
            _ => fail!("unexpected type")
        };

        let base_offset = node_number * record_size / 4;

        let bytes = match record_size {
            24 => {
                let offset = base_offset + index * 3;
                read_from_map(&self.decoder.map, 3, offset)
            },
            28 => {
                let mut middle = read_from_map(&self.decoder.map, 1, base_offset + 3)[0];
                if index != 0 {
                    middle &= 0x0F
                } else {
                    middle = (0xF0 & middle) >> 4
                }
                let offset = base_offset + index * 4;
                [middle] + read_from_map(&self.decoder.map, 3, offset)
            },
            32 => {
                let offset = base_offset + index * 4;
                read_from_map(&self.decoder.map, 4, offset)
            },
            s => return Err(InvalidDatabaseError(format!("unknown record size: {}", s)))
        };
        let mut reader = BufReader::new(bytes);
        Ok(reader.read_be_uint_n(bytes.len()).unwrap() as uint)
    }

    fn resolve_data_pointer(&self, pointer: uint) -> Result<DataRecord, Error> {
        let node_count = match self.metadata.find(&~"node_count").unwrap() {
            &Uint64(i) => i as uint,
            _ => fail!("unexpected type")
        };

        let record_size = match self.metadata.find(&~"record_size").unwrap() {
            &Uint64(i) => i as uint,
            _ => fail!("unexpected type")
        };

        let search_tree_size = record_size * node_count / 4;

        let resolved = pointer - node_count + search_tree_size;
        print!("resolved: {} {}\n", resolved, self.decoder.map.len);

        if resolved > self.decoder.map.len  {
            return Err(InvalidDatabaseError(~"the MaxMind DB file's search tree is corrupt"));
        }

        let (record, _) = self.decoder.decode(resolved);
        record
    }
}

fn read_from_map(map: &os::MemoryMap, size: uint, offset: uint) -> ~[u8] {
    unsafe { std::slice::from_buf(map.data.offset(offset as int) as *u8, size)}
}

fn ip_to_bytes(ip_address: IpAddr) -> ~[u8] {
    match ip_address {
        Ipv4Addr(a, b, c, d) => ~[a, b, c, d],
        // Ipv4 Compatible address
        Ipv6Addr(0, 0, 0, 0, 0, 0 , g, h) |
        Ipv6Addr(0, 0, 0, 0, 0, 0xFFFF , g, h) => ~[
                                            (g >> 8) as u8, g as u8,
                                            (h >> 8) as u8, h as u8
                                         ],
        Ipv6Addr(a, b, c, d, e, f, g, h) => ~[
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

fn find_metadata_start(map: &os::MemoryMap) -> uint {
    // This is reversed to make the loop below a bit simpler
    let metadata_start_marker : [u8, ..14] = [ 0x6d, 0x6f, 0x63, 0x2e, 0x64,
                                               0x6e, 0x69, 0x4d, 0x78, 0x61,
                                               0x4d, 0xEF, 0xCD, 0xAB,
                                             ];
    let marker_length = metadata_start_marker.len();

    // XXX - ugly code
    for start_position in range(marker_length, map.len) {
        let mut not_found = false;
        for (offset, marker_byte) in metadata_start_marker.iter().enumerate() {
            let file_byte = unsafe {
                *(map.data.offset(
                    (map.len - start_position - offset -1 ) as int
                    ))
            };
            if file_byte != *marker_byte {
                not_found = true;
                break;
            }
        }
        if !not_found {
            return map.len - start_position;
        }
    }
    fail!("Could not find MaxMind DB metadata in file.");
}

fn main() {
    let mut r = Reader::open("GeoLite2-City.mmdb");
    let ip: IpAddr = FromStr::from_str("1.1.1.1").unwrap();
    print!("{}", r.lookup(ip))
}

