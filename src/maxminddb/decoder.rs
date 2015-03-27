extern crate rustc_serialize;

use std::string;

use super::{ DataRecord, Error,};
use super::DataRecord::{Array, Boolean, Byte, Double, Float, Int32, Map,
                        Null, String, Uint16, Uint32, Uint64};
use super::Error::DecodingError;

macro_rules! expect(
    ($e:expr, Null) => ({
        match $e {
            Null => Ok(()),
            other => Err(DecodingError(format!("Error decoding Null as {:?}", other)))
        }
    });
    ($e:expr, $t:ident) => ({
        match $e {
            $t(v) => Ok(v),
            other => Err(DecodingError(format!("Error decoding {:?} as {:?}", other, stringify!($t))))
        }
    })
);

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
impl rustc_serialize::Decoder for Decoder {
    type Error = Error;

    fn read_nil(&mut self) -> DecodeResult<()> {
        debug!("read_nil");
        expect!(self.pop(), Null)
    }

    fn read_u64(&mut self)  -> DecodeResult<u64> {
        debug!("read_u64");
        Ok(try!(expect!(self.pop(), Uint64)))
    }

    fn read_u32(&mut self)  -> DecodeResult<u32> {
        debug!("read_u32");
        Ok(try!(expect!(self.pop(), Uint32)))
    }

    fn read_u16(&mut self)  -> DecodeResult<u16> {
        debug!("read_u16");
        Ok(try!(expect!(self.pop(), Uint16)))
    }

    fn read_u8 (&mut self)  -> DecodeResult<u8> {
        debug!("read_u8");
        Ok(try!(expect!(self.pop(), Byte)))
    }

    fn read_usize(&mut self) -> DecodeResult<usize> {
        debug!("read_usize");
        Ok(try!(expect!(self.pop(), Uint32)) as usize)
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
        Err(DecodingError("i16 data not supported by MaxMind DB format".to_string()))
    }

    fn read_i8 (&mut self) -> DecodeResult<i8 > {
        debug!("read_i8");
        Err(DecodingError("i8 data not supported by MaxMind DB format".to_string()))
    }

    fn read_isize(&mut self) -> DecodeResult<isize> {
        debug!("read_int");
        Ok(try!(self.read_i32()) as isize)
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
        Err(DecodingError(format!("char {:?}", s)))
    }

    fn read_str(&mut self) -> DecodeResult<string::String> {
        debug!("read_str");
        Ok(try!(expect!(self.pop(), String)))
    }

   fn read_enum<T, F>(&mut self, name: &str, f: F) -> DecodeResult<T> where
        F: FnOnce(&mut Decoder) -> DecodeResult<T> {
        debug!("read_enum({:?})", name);
        f(self)
    }

    fn read_enum_variant<T, F>(&mut self, names: &[&str], f: F) -> DecodeResult<T> where
        F: FnOnce(&mut Decoder, usize) -> DecodeResult<T> {

        debug!("read_enum_variant(names={:?})", names);
        let name = match self.pop() {
            String(s) => s,
            Map(mut o) => {
                let n = match o.remove(&"variant".to_string()) {
                    Some(String(s)) => s,
                    Some(val) => return Err(DecodingError( format!("enum {:?}", val))),
                    None => return Err(DecodingError("variant".to_string()))
                };
                match o.remove(&"fields".to_string()) {
                    Some(Array(l)) => {
                        for field in l.into_iter().rev() {
                            self.stack.push(field.clone());
                        }
                    },
                    Some(val) => return Err(DecodingError(format!("enum {:?}", val))),
                    None => return Err(DecodingError("fields".to_string()))
                }
                n
            }
            json => return Err(DecodingError( format!("enum {:?}", json)))
        };
        let idx = match names.iter()
                             .position(|n| {
                                 *n == name
                             }) {
            Some(idx) => idx,
            None => return Err(DecodingError(name))
        };
        f(self, idx)
    }

    fn read_enum_variant_arg<T, F>(&mut self, idx: usize, f: F) -> DecodeResult<T> where
        F: FnOnce(&mut Decoder) -> DecodeResult<T> {
        debug!("read_enum_variant_arg(idx={:?})", idx);
        f(self)
    }

    fn read_enum_struct_variant<T, F>(&mut self, names: &[&str], f: F) -> DecodeResult<T> where
        F: FnMut(&mut Decoder, usize) -> DecodeResult<T> {
        debug!("read_enum_struct_variant(names={:?})", names);
        self.read_enum_variant(names, f)
    }


    fn read_enum_struct_variant_field<T, F>(&mut self,
                                         name: &str,
                                         idx: usize,
                                         f: F)
                                         -> DecodeResult<T> where
                                         F: FnOnce(&mut Decoder)
                                         -> DecodeResult<T> {
        debug!("read_enum_struct_variant_field(name={:?}, idx={:?})", name, idx);
        self.read_enum_variant_arg(idx, f)
    }

    fn read_struct<T, F>(&mut self, name: &str, len: usize, f: F) -> DecodeResult<T> where
        F: FnOnce(&mut Decoder) -> DecodeResult<T> {
        debug!("read_struct(name={:?}, len={:?})", name, len);
        let value = try!(f(self));
        self.pop();
        Ok(value)
    }

    fn read_struct_field<T, F>(&mut self,
                               name: &str,
                               idx: usize,
                               f: F)
                               -> DecodeResult<T> where
                               F: FnOnce(&mut Decoder)
                               -> DecodeResult<T> {
        debug!("read_struct_field(name={:?}, idx={:?})", name, idx);
        let mut obj = try!(expect!(self.pop(), Map));

        let value = match obj.remove(&name.to_string()) {
            None => {
                self.stack.push(Null);
                match f(self) {
                    Ok(v) => v,
                    Err(_) =>  return Err(DecodingError(format!("Unknown struct field {:?}", name.to_string()))),
                }
            },
            Some(record) => {
                self.stack.push(record);
                try!(f(self))
            }
        };
        self.stack.push(Map(obj));
        Ok(value)
    }

    fn read_tuple<T, F>(&mut self, tuple_len: usize, f: F) -> DecodeResult<T> where
        F: FnOnce(&mut Decoder) -> DecodeResult<T> {
        debug!("read_tuple()");
        self.read_seq(move |d, len| {
            if len == tuple_len {
                f(d)
            } else {
                Err(DecodingError(format!("Tuple{:?}", tuple_len)))
            }
        })
    }

    fn read_tuple_arg<T, F>(&mut self, idx: usize, f: F) -> DecodeResult<T> where
        F: FnOnce(&mut Decoder) -> DecodeResult<T> {
        debug!("read_tuple_arg(idx={:?})", idx);
        self.read_seq_elt(idx, f)
    }

    fn read_tuple_struct<T, F>(&mut self,
                               name: &str,
                               len: usize,
                               f: F)
                               -> DecodeResult<T> where
                               F: FnOnce(&mut Decoder) -> DecodeResult<T> {
        debug!("read_tuple_struct(name={:?})", name);
        self.read_tuple(len, f)
    }

    fn read_tuple_struct_arg<T, F>(&mut self,
                                   idx: usize,
                                   f: F)
                                   -> DecodeResult<T> where
        F: FnOnce(&mut Decoder) -> DecodeResult<T> {
        debug!("read_tuple_struct_arg(idx={:?})", idx);
        self.read_tuple_arg(idx, f)
    }

    fn read_option<T, F>(&mut self, f: F) -> DecodeResult<T> where
        F: FnOnce(&mut Decoder, bool) -> DecodeResult<T> {
        debug!("read_option()");
        match self.pop() {
            Null => f(self, false),
            value => { self.stack.push(value); f(self, true) }
        }
    }

    fn read_seq<T, F>(&mut self, f: F) -> DecodeResult<T> where
        F: FnOnce(&mut Decoder, usize) -> DecodeResult<T> {
        debug!("read_seq()");
        let list = try!(expect!(self.pop(), Array));
        let len = list.len();
        for v in list.into_iter().rev() {
            self.stack.push(v);
        }
        f(self, len)
    }

    fn read_seq_elt<T, F>(&mut self, idx: usize, f: F) -> DecodeResult<T> where
        F: FnOnce(&mut Decoder) -> DecodeResult<T> {
        debug!("read_seq_elt(idx={:?})", idx);
        f(self)
    }

    fn read_map<T, F>(&mut self, f: F) -> DecodeResult<T> where
        F: FnOnce(&mut Decoder, usize) -> DecodeResult<T> {
        debug!("read_map()");
        let obj = try!(expect!(self.pop(), Map));
        let len = obj.len();
        for (key, value) in obj.into_iter() {
            self.stack.push(value);
            self.stack.push(String(key));
        }
        f(self, len)
    }

    fn read_map_elt_key<T, F>(&mut self, idx: usize, f: F) -> DecodeResult<T> where
       F: FnOnce(&mut Decoder) -> DecodeResult<T> {
        debug!("read_map_elt_key(idx={:?})", idx);
        f(self)
    }

    fn read_map_elt_val<T, F>(&mut self, idx: usize, f: F) -> DecodeResult<T> where
       F: FnOnce(&mut Decoder) -> DecodeResult<T> {
        debug!("read_map_elt_val(idx={:?})", idx);
        f(self)
    }

    fn error(&mut self, err: &str) -> Error {
        DecodingError(err.to_string())
    }
}
