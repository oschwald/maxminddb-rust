extern crate serialize;

use std::str;

use serialize::Decoder;

use super::{Array, Boolean, Byte, DataRecord, DecodingError, Double, Error,
            Float, Int32, Map, String, Uint16, Uint32, Uint64};

macro_rules! expect(
    ($e:expr, $t:ident) => ({
        match $e {
            $t(v) => Ok(v),
            other => Err(DecodingError(format_strbuf!("Error decoding {:?} as {}", other, stringify!($t))))
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
        Err(DecodingError("nil data not supported by MaxMind DB format".to_strbuf()))
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
        Ok(try!(expect!(self.pop(), Byte)))
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
        Err(DecodingError("i16 data not supported by MaxMind DB format".to_strbuf()))
    }

    fn read_i8 (&mut self) -> DecodeResult<i8 > {
        debug!("read_i8");
        Err(DecodingError("i8 data not supported by MaxMind DB format".to_strbuf()))
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
            let mut it = s.as_slice().chars();
            match (it.next(), it.next()) {
                // exactly one character
                (Some(c), None) => return Ok(c),
                _ => ()
            }
        }
        Err(DecodingError(format_strbuf!("char {}", s)))
    }

    fn read_str(&mut self) -> DecodeResult<String> {
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
                let n = match o.pop(&"variant".to_strbuf()) {
                    Some(String(s)) => s,
                    Some(val) => return Err(DecodingError( format_strbuf!("enum {}", val))),
                    None => return Err(DecodingError("variant".to_strbuf()))
                };
                match o.pop(&"fields".to_strbuf()) {
                    Some(Array(l)) => {
                        for field in l.move_iter().rev() {
                            self.stack.push(field.clone());
                        }
                    },
                    Some(val) => return Err(DecodingError(format_strbuf!("enum {}", val))),
                    None => return Err(DecodingError("fields".to_strbuf()))
                }
                n
            }
            json => return Err(DecodingError( format_strbuf!("enum {}", json)))
        };
        let idx = match names.iter()
                             .position(|n| {
                                 str::eq_slice(*n, name.as_slice())
                             }) {
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

        let value = match obj.pop(&name.to_strbuf()) {
            None => return Err(DecodingError(format_strbuf!("Unknown struct field {}", name.to_strbuf()))),
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
