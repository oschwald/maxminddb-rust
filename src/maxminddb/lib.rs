#![crate_id = "maxminddb#0.1.0-pre"]

#![comment = "MaxMind DB Reader"]
#![license = "Apache 2"]
#![crate_type = "dylib"]
#![crate_type = "rlib"]

#![feature(macro_rules)]

#![feature(phase)]
#[phase(syntax, link)] extern crate log;

extern crate collections;
extern crate native;
extern crate serialize;

use std::fmt;
use std::io::BufReader;
use std::io::{Open, Read};
use std::io::net::ip::{IpAddr,Ipv6Addr,Ipv4Addr};
use std::os;
use std::str;

use collections::TreeMap;
use serialize::{Decoder, Decodable};

#[deriving(Eq, Show)]
pub enum Error {
    InvalidDatabaseError(~str),
    IoError(std::io::IoError),
    MapError(~str),
    DecodingError(~str),
}

pub type BinaryDecodeResult<T> = (Result<T, Error>, uint);

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

#[deriving(Decodable)]
struct Metadata {
    binary_format_major_version : u16,
    binary_format_minor_version : u16,
    build_epoch                 : u64,
    database_type               : ~str,
    description                 : TreeMap<~str, ~str>,
    ip_version                  : u16,
    languages                   : ~[~str],
    node_count                  : uint,
    record_size                 : u16,
}

struct BinaryDecoder {
    map      : os::MemoryMap,
    pointer_base: uint
}

impl BinaryDecoder {
    fn decode_array(&self, size: uint, offset: uint) -> BinaryDecodeResult<DataRecord> {
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

    fn decode_bool(&self, size: uint, offset: uint) -> BinaryDecodeResult<DataRecord> {
        (Ok(Boolean(size != 0)), offset)
    }

    fn decode_bytes(&self, size: uint, offset: uint) -> BinaryDecodeResult<DataRecord> {
        let new_offset = offset + size;
        let bytes = read_from_map(&self.map, size, offset);
        (Ok(Bytes(bytes)), new_offset)
    }

    fn decode_float(&self, size: uint, offset: uint) -> BinaryDecodeResult<DataRecord> {
        let new_offset = offset + size;

        let buf = read_from_map(&self.map, size, offset);
        let mut reader = BufReader::new(buf);
        (Ok(Float(reader.read_be_f32().unwrap())), new_offset)
    }

    fn decode_double(&self, size: uint, offset: uint) -> BinaryDecodeResult<DataRecord> {
        let new_offset = offset + size;

        let buf = read_from_map(&self.map, size, offset);
        let mut reader = BufReader::new(buf);
        (Ok(Double(reader.read_be_f64().unwrap())), new_offset)
    }

    fn decode_uint64(&self, size: uint, offset: uint) -> BinaryDecodeResult<DataRecord> {
        let new_offset = offset + size;

        let value = if size == 0 {
                0
            } else {
                let buf = read_from_map(&self.map, size, offset);
                let mut reader = BufReader::new(buf);
                reader.read_be_uint_n(size).unwrap()
            };

        (Ok(Uint64(value)), new_offset)
    }

    fn decode_uint32(&self, size: uint, offset: uint) -> BinaryDecodeResult<DataRecord> {
        match self.decode_uint64(size, offset) {
            (Ok(Uint64(u)), o) => (Ok(Uint32(u as u32)), o),
            e => e
        }
    }

    fn decode_uint16(&self, size: uint, offset: uint) -> BinaryDecodeResult<DataRecord> {
        match self.decode_uint64(size, offset) {
            (Ok(Uint64(u)), o) => (Ok(Uint16(u as u16)), o),
            e => e
        }
    }

    fn decode_int(&self, size: uint, offset: uint) -> BinaryDecodeResult<DataRecord> {
        let new_offset = offset + size;

        let buf = read_from_map(&self.map, size, offset);
        let mut reader = BufReader::new(buf);
        (Ok(Int32(reader.read_be_int_n(size).unwrap() as i32)), new_offset)
    }

    fn decode_map(&self, size: uint, offset: uint) -> BinaryDecodeResult<DataRecord> {
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
                v => return (Err(InvalidDatabaseError(format!("unexpected map key type {}", v))), 0)
            };
            values.insert(str_key, val);
        }
        (Ok(Map(values)), new_offset)
    }


    fn decode_pointer(&self, size: uint, offset: uint) -> BinaryDecodeResult<DataRecord> {
        let pointer_value_offset = [0, 0, 2048, 526336, 0];
        let pointer_size = ((size >> 3) & 0x3) + 1;
        let new_offset = offset + pointer_size;
        let pointer_bytes = read_from_map(&self.map, pointer_size, offset);

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

    fn decode_string(&self, size: uint, offset: uint) -> BinaryDecodeResult<DataRecord> {
        let new_offset : uint = offset + size;
        let bytes = read_from_map(&self.map, size, offset);
        match str::from_utf8(bytes) {
            Some(v) => (Ok(String(v.to_str())), new_offset),
            None => (Err(InvalidDatabaseError("error decoding string".to_owned())), new_offset)
        }
    }

    fn decode(&self, offset: uint) -> BinaryDecodeResult<DataRecord> {
        let mut new_offset = offset + 1;
        let ctrl_byte = (read_from_map(&self.map, 1, offset))[0];

        let mut type_num = ctrl_byte >> 5;

        // Extended type
        if type_num == 0 {
            type_num = read_from_map(&self.map, 1, new_offset)[0] + 7;
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
        let size_bytes = read_from_map(&self.map, bytes_to_read, offset);

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

    fn decode_from_type(&self, data_type: u8, size: uint, offset: uint) -> BinaryDecodeResult<DataRecord> {
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
            10 => (Err(InvalidDatabaseError("128 bit uint support is not implemented".to_owned())), offset),
            11 => self.decode_array(size, offset),
            14 => self.decode_bool(size, offset),
            15 => self.decode_float(size, offset),
            u  => (Err(InvalidDatabaseError(format!("Unknown data type: {}", u))), offset),
        }
    }
}

macro_rules! expect(
    ($e:expr, $t:ident) => ({
        match $e {
            $t(v) => Ok(v),
            other => Err(DecodingError(format!("Error deocoding {:?} as {}", other, stringify!($t))))
        }
    })
)

pub struct Decoder {
    stack: Vec<DataRecord>,
}

impl Decoder {
    /// Creates a new decoder instance for decoding the specified JSON value.
    pub fn new(record: DataRecord) -> Decoder {
        Decoder {
            stack: vec!(record),
        }
    }
}

impl Decoder {
    fn pop(&mut self) -> DataRecord {
        self.stack.pop().unwrap()
    }
}

pub type DecodeResult<T> = Result<T, Error>;

// Much of this code was borrowed from the Rust JSON library
impl serialize::Decoder<Error> for Decoder {
    fn read_nil(&mut self) -> DecodeResult<()> {
        debug!("read_nil");
        Err(DecodingError("nil data not supported by MaxMind DB format".to_owned()))
    }

    fn read_u64(&mut self)  -> DecodeResult<u64 > {
        debug!("read_u64");
        Ok(try!(expect!(self.pop(), Uint64)))
    }

    fn read_u32(&mut self)  -> DecodeResult<u32 > {
        debug!("read_u32");
        Ok(try!(expect!(self.pop(), Uint32)))
    }

    fn read_u16(&mut self)  -> DecodeResult<u16 > {
        debug!("read_u16");
        Ok(try!(expect!(self.pop(), Uint16)))
    }

    fn read_u8 (&mut self)  -> DecodeResult<u8  > {
        debug!("read_u8");
        Err(DecodingError("u8 data not supported by MaxMind DB format".to_owned()))
    }

    fn read_uint(&mut self) -> DecodeResult<uint> {
        debug!("read_uint");
        Ok(try!(expect!(self.pop(), Uint32)) as uint)
    }

    fn read_i64(&mut self) -> DecodeResult<i64> {
        debug!("read_i64");
        Ok(try!(self.read_i32()) as i64)
    }

    fn read_i32(&mut self) -> DecodeResult<i32> {
        debug!("read_i32");
        Ok(try!(expect!(self.pop(), Int32)))
    }

    fn read_i16(&mut self) -> DecodeResult<i16> {
        debug!("read_i16");
        Err(DecodingError("i16 data not supported by MaxMind DB format".to_owned()))
    }

    fn read_i8 (&mut self) -> DecodeResult<i8 > {
        debug!("read_i8");
        Err(DecodingError("i8 data not supported by MaxMind DB format".to_owned()))
    }

    fn read_int(&mut self) -> DecodeResult<int> {
        debug!("read_int");
        Ok(try!(self.read_i32()) as int)
    }

    fn read_bool(&mut self) -> DecodeResult<bool> {
        debug!("read_bool");
        Ok(try!(expect!(self.pop(), Boolean)))
    }

    fn read_f64(&mut self) -> DecodeResult<f64> {
        debug!("read_f64");
        Ok(try!(expect!(self.pop(), Double)))
    }

    fn read_f32(&mut self) -> DecodeResult<f32> {
        debug!("read_f32");
        Ok(try!(expect!(self.pop(), Float)))
    }

    fn read_char(&mut self) -> DecodeResult<char> {
        let s = try!(self.read_str());
        {
            let mut it = s.chars();
            match (it.next(), it.next()) {
                // exactly one character
                (Some(c), None) => return Ok(c),
                _ => ()
            }
        }
        Err(DecodingError(format!("char {}", s)))
    }

    fn read_str(&mut self) -> DecodeResult<~str> {
        debug!("read_str");
        Ok(try!(expect!(self.pop(), String)))
    }

    fn read_enum<T>(&mut self,
                    name: &str,
                    f: |&mut Decoder| -> DecodeResult<T>) -> DecodeResult<T> {
        debug!("read_enum({})", name);
        f(self)
    }

    fn read_enum_variant<T>(&mut self,
                            names: &[&str],
                            f: |&mut Decoder, uint| -> DecodeResult<T>)
                            -> DecodeResult<T> {
        debug!("read_enum_variant(names={:?})", names);
        let name = match self.pop() {
            String(s) => s,
            Map(mut o) => {
                let n = match o.pop(&"variant".to_owned()) {
                    Some(String(s)) => s,
                    Some(val) => return Err(DecodingError( format!("enum {}", val))),
                    None => return Err(DecodingError("variant".to_owned()))
                };
                match o.pop(&"fields".to_owned()) {
                    Some(Array(l)) => {
                        for field in l.move_iter().rev() {
                            self.stack.push(field.clone());
                        }
                    },
                    Some(val) => return Err(DecodingError(format!("enum {}", val))),
                    None => return Err(DecodingError("fields".to_owned()))
                }
                n
            }
            json => return Err(DecodingError( format!("enum {}", json)))
        };
        let idx = match names.iter().position(|n| str::eq_slice(*n, name)) {
            Some(idx) => idx,
            None => return Err(DecodingError(name))
        };
        f(self, idx)
    }

    fn read_enum_variant_arg<T>(&mut self, idx: uint, f: |&mut Decoder| -> DecodeResult<T>)
                                -> DecodeResult<T> {
        debug!("read_enum_variant_arg(idx={})", idx);
        f(self)
    }

    fn read_enum_struct_variant<T>(&mut self,
                                   names: &[&str],
                                   f: |&mut Decoder, uint| -> DecodeResult<T>)
                                   -> DecodeResult<T> {
        debug!("read_enum_struct_variant(names={:?})", names);
        self.read_enum_variant(names, f)
    }


    fn read_enum_struct_variant_field<T>(&mut self,
                                         name: &str,
                                         idx: uint,
                                         f: |&mut Decoder| -> DecodeResult<T>)
                                         -> DecodeResult<T> {
        debug!("read_enum_struct_variant_field(name={}, idx={})", name, idx);
        self.read_enum_variant_arg(idx, f)
    }

    fn read_struct<T>(&mut self,
                      name: &str,
                      len: uint,
                      f: |&mut Decoder| -> DecodeResult<T>)
                      -> DecodeResult<T> {
        debug!("read_struct(name={}, len={})", name, len);
        let value = try!(f(self));
        self.pop();
        Ok(value)
    }

    fn read_struct_field<T>(&mut self,
                            name: &str,
                            idx: uint,
                            f: |&mut Decoder| -> DecodeResult<T>)
                            -> DecodeResult<T> {
        debug!("read_struct_field(name={}, idx={})", name, idx);
        let mut obj = try!(expect!(self.pop(), Map));

        let value = match obj.pop(&name.to_owned()) {
            None => return Err(DecodingError(format!("struct {}", name.to_owned()))),
            Some(record) => {
                self.stack.push(record);
                try!(f(self))
            }
        };
        self.stack.push(Map(obj));
        Ok(value)
    }

    fn read_tuple<T>(&mut self, f: |&mut Decoder, uint| -> DecodeResult<T>) -> DecodeResult<T> {
        debug!("read_tuple()");
        self.read_seq(f)
    }

    fn read_tuple_arg<T>(&mut self,
                         idx: uint,
                         f: |&mut Decoder| -> DecodeResult<T>) -> DecodeResult<T> {
        debug!("read_tuple_arg(idx={})", idx);
        self.read_seq_elt(idx, f)
    }

    fn read_tuple_struct<T>(&mut self,
                            name: &str,
                            f: |&mut Decoder, uint| -> DecodeResult<T>)
                            -> DecodeResult<T> {
        debug!("read_tuple_struct(name={})", name);
        self.read_tuple(f)
    }

    fn read_tuple_struct_arg<T>(&mut self,
                                idx: uint,
                                f: |&mut Decoder| -> DecodeResult<T>)
                                -> DecodeResult<T> {
        debug!("read_tuple_struct_arg(idx={})", idx);
        self.read_tuple_arg(idx, f)
    }

    fn read_option<T>(&mut self, f: |&mut Decoder, bool| -> DecodeResult<T>) -> DecodeResult<T> {
        let value = self.pop();
        self.stack.push(value);
        f(self, true)
    }

    fn read_seq<T>(&mut self, f: |&mut Decoder, uint| -> DecodeResult<T>) -> DecodeResult<T> {
        debug!("read_seq()");
        let list = try!(expect!(self.pop(), Array));
        let len = list.len();
        for v in list.move_iter().rev() {
            self.stack.push(v);
        }
        f(self, len)
    }

    fn read_seq_elt<T>(&mut self,
                       idx: uint,
                       f: |&mut Decoder| -> DecodeResult<T>) -> DecodeResult<T> {
        debug!("read_seq_elt(idx={})", idx);
        f(self)
    }

    fn read_map<T>(&mut self, f: |&mut Decoder, uint| -> DecodeResult<T>) -> DecodeResult<T> {
        debug!("read_map()");
        let obj = try!(expect!(self.pop(), Map));
        let len = obj.len();
        for (key, value) in obj.move_iter() {
            self.stack.push(value);
            self.stack.push(String(key));
        }
        f(self, len)
    }

    fn read_map_elt_key<T>(&mut self, idx: uint, f: |&mut Decoder| -> DecodeResult<T>)
                           -> DecodeResult<T> {
        debug!("read_map_elt_key(idx={})", idx);
        f(self)
    }

    fn read_map_elt_val<T>(&mut self, idx: uint, f: |&mut Decoder| -> DecodeResult<T>)
                           -> DecodeResult<T> {
        debug!("read_map_elt_val(idx={})", idx);
        f(self)
    }
}

pub struct Reader {
    decoder: BinaryDecoder,
    metadata: Metadata,
    ipv4_start: uint,
}

impl Reader {

    pub fn open(database: &str) -> Result<Reader, Error> {
        let data_section_separator_size = 16;

        let f = match native::io::file::open(&database.to_c_str(),
                                             Open, Read) {
            Ok(f)  => f,
            Err(e) => return Err(IoError(e))
        };
        let fd = f.fd();

        let stats = match native::io::file::stat(&database.to_c_str()) {
            Ok(s) => s,
            Err(e) => return Err(IoError(e))
        };

        let database_size = stats.size as uint;
        let map = match os::MemoryMap::new(database_size, [os::MapReadable, os::MapFd(fd), os::MapOffset(0)])
        {
            Ok(mem)  => mem,
            Err(msg) => return Err(MapError(msg.to_str()))
        };

        let metadata_start = match find_metadata_start(&map) {
            Ok(i) => i,
            Err(e) => return Err(e)
        };
        let metadata_decoder = BinaryDecoder { map: map, pointer_base: metadata_start};

        let raw_metadata = match metadata_decoder.decode(metadata_start) {
            (Ok(m), _) => m,
            m      => return Err(InvalidDatabaseError(format!("metadata of wrong type: {}", m))),
        };

        let mut typeDecoder = ::Decoder::new(raw_metadata);
        let metadata: Metadata = match Decodable::decode(&mut typeDecoder) {
            Ok(v) => v,
            Err(e) => fail!("Decoding error: {}", e)
        };

        let search_tree_size = metadata.node_count * (metadata.record_size as uint) / 4;
        let decoder = BinaryDecoder{map: metadata_decoder.map, pointer_base: search_tree_size as uint + data_section_separator_size};

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
        self.resolve_data_pointer(pointer)
    }

    fn find_address_in_tree(&self, ip_address: ~[u8]) -> Result<uint, Error> {
        let bit_count = ip_address.len()*8;
        let mut node = self.start_node(bit_count).unwrap();

        for i in range(0, bit_count) {
            if node >= self.metadata.node_count {
                break;
            }
            let bit = 1 & (ip_address[i>>3] >> (7-(i % 8)));

            node = match self.read_node(node, bit as uint) {
                Ok(v) => v,
                e => return e
            };
        }
        if node == self.metadata.node_count {
            Ok(0)
        } else if node > self.metadata.node_count {
            Ok(node)
        } else {
           Err(InvalidDatabaseError("invalid node in search tree".to_owned()))
        }
    }

    fn start_node(&self, length: uint) -> Result<uint, Error> {
        if length == 128 {
            Ok(0)
        } else {
            Ok(self.ipv4_start)
        }
    }

    fn find_ipv4_start(&self)  -> Result<uint, Error> {

        if self.metadata.ip_version != 6 {
            return Ok(0);
        }

        // We are looking up an IPv4 address in an IPv6 tree. Skip over the
        // first 96 nodes.
        let mut node: uint = 0u;
        for _ in range(0, 96) {
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


    fn read_node(&self, node_number: uint, index: uint) -> Result<uint, Error> {

        let base_offset = node_number * (self.metadata.record_size as uint)/ 4;

        let bytes = match self.metadata.record_size {
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
        let search_tree_size = (self.metadata.record_size as uint) * self.metadata.node_count / 4;

        let resolved = pointer - self.metadata.node_count + search_tree_size;

        if resolved > self.decoder.map.len  {
            return Err(InvalidDatabaseError("the MaxMind DB file's search tree is corrupt".to_owned()));
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

fn find_metadata_start(map: &os::MemoryMap) -> Result<uint, Error> {
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
            return Ok(map.len - start_position);
        }
    }
    Err(InvalidDatabaseError("Could not find MaxMind DB metadata in file.".to_owned()))
}

