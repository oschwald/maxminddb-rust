use std::collections::BTreeMap;
use std::string;

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};

use super::MaxMindDBError;
use super::MaxMindDBError::DecodingError;

pub type DbArray = Vec<DataRecord>;
pub type DbMap = BTreeMap<string::String, DataRecord>;

#[derive(Clone, Debug, PartialEq)]
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

use self::DataRecord::{
    Array, Boolean, Byte, Double, Float, Int32, Map, Null, String, Uint16, Uint32, Uint64,
};

macro_rules! expect(
    ($e:expr, $t:ident) => ({
        match $e {
            $t(v) => Ok(v),
            other => Err(DecodingError(format!("Error decoding {:?} as {:?}",
                         other, stringify!($t))))
        }
    })
);

#[derive(Debug)]
pub struct Decoder {
    stack: Vec<DataRecord>,
}

impl Decoder {
    /// Creates a new decoder instance for decoding the specified JSON value.
    pub fn new(record: DataRecord) -> Decoder {
        Decoder {
            stack: vec![record],
        }
    }
}

impl Decoder {
    fn pop(&mut self) -> DataRecord {
        self.stack.pop().unwrap()
    }

    fn peek(&self) -> Option<&DataRecord> {
        self.stack.get(self.stack.len() - 1)
    }
}

pub type DecodeResult<T> = Result<T, MaxMindDBError>;

// Much of this code was borrowed from the Rust JSON library, Serde Deserializer example
impl<'de, 'a> de::Deserializer<'de> for &'a mut Decoder {
    type Error = MaxMindDBError;

    #[inline]
    fn deserialize_any<V>(self, visitor: V) -> DecodeResult<V::Value>
    where
        V: Visitor<'de>,
    {
        debug!("deserialize_any");
        match self.peek() {
            Some(&String(_)) => self.deserialize_str(visitor),
            Some(&Double(_)) => self.deserialize_f64(visitor),
            Some(&Byte(_)) => self.deserialize_u8(visitor),
            Some(&Uint16(_)) => self.deserialize_u16(visitor),
            Some(&Uint32(_)) => self.deserialize_u32(visitor),
            Some(&Map(_)) => self.deserialize_map(visitor),
            Some(&Int32(_)) => self.deserialize_i32(visitor),
            Some(&Uint64(_)) => self.deserialize_u64(visitor),
            Some(&Boolean(_)) => self.deserialize_bool(visitor),
            Some(&Array(_)) => self.deserialize_seq(visitor),
            Some(&Float(_)) => self.deserialize_f32(visitor),
            Some(&Null) => self.deserialize_unit(visitor),
            None => Err(DecodingError("nothing left to deserialize".to_owned())),
        }
    }

    fn deserialize_u64<V>(self, visitor: V) -> DecodeResult<V::Value>
    where
        V: Visitor<'de>,
    {
        debug!("read_u64");
        visitor.visit_u64(expect!(self.pop(), Uint64)?)
    }

    fn deserialize_u32<V>(self, visitor: V) -> DecodeResult<V::Value>
    where
        V: Visitor<'de>,
    {
        debug!("read_u32");
        visitor.visit_u32(expect!(self.pop(), Uint32)?)
    }

    fn deserialize_u16<V>(self, visitor: V) -> DecodeResult<V::Value>
    where
        V: Visitor<'de>,
    {
        debug!("read_u16");
        visitor.visit_u16(expect!(self.pop(), Uint16)?)
    }

    fn deserialize_u8<V>(self, visitor: V) -> DecodeResult<V::Value>
    where
        V: Visitor<'de>,
    {
        debug!("read_u8");
        visitor.visit_u8(expect!(self.pop(), Byte)?)
    }

    fn deserialize_i64<V>(self, visitor: V) -> DecodeResult<V::Value>
    where
        V: Visitor<'de>,
    {
        debug!("read_i64");
        self.deserialize_i32(visitor)
    }

    fn deserialize_i32<V>(self, visitor: V) -> DecodeResult<V::Value>
    where
        V: Visitor<'de>,
    {
        debug!("read_i32");
        visitor.visit_i32(expect!(self.pop(), Int32)?)
    }

    fn deserialize_bool<V>(self, visitor: V) -> DecodeResult<V::Value>
    where
        V: Visitor<'de>,
    {
        debug!("read_bool");
        visitor.visit_bool(expect!(self.pop(), Boolean)?)
    }

    fn deserialize_f64<V>(self, visitor: V) -> DecodeResult<V::Value>
    where
        V: Visitor<'de>,
    {
        debug!("read_f64");
        visitor.visit_f64(expect!(self.pop(), Double)?)
    }

    fn deserialize_f32<V>(self, visitor: V) -> DecodeResult<V::Value>
    where
        V: Visitor<'de>,
    {
        debug!("read_f32");
        visitor.visit_f32(expect!(self.pop(), Float)?)
    }

    fn deserialize_str<V>(self, visitor: V) -> DecodeResult<V::Value>
    where
        V: Visitor<'de>,
    {
        let string = expect!(self.pop(), String)?;
        debug!("read_str: {}", string);
        visitor.visit_str(&string)
    }

    fn deserialize_string<V>(self, visitor: V) -> DecodeResult<V::Value>
    where
        V: Visitor<'de>,
    {
        debug!("read_string");
        self.deserialize_str(visitor)
    }

    // Structs look just like maps in JSON.
    //
    // Notice the `fields` parameter - a "struct" in the Serde data model means
    // that the `Deserialize` implementation is required to know what the fields
    // are before even looking at the input data. Any key-value pairing in which
    // the fields cannot be known ahead of time is probably a map.
    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> DecodeResult<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_map(visitor)
    }

    // Tuples look just like sequences in JSON. Some formats may be able to
    // represent tuples more efficiently.
    //
    // As indicated by the length parameter, the `Deserialize` implementation
    // for a tuple in the Serde data model is required to know the length of the
    // tuple before even looking at the input data.
    fn deserialize_tuple<V>(self, _len: usize, visitor: V) -> DecodeResult<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_seq(visitor)
    }

    // Tuple structs look just like sequences in JSON.
    fn deserialize_tuple_struct<V>(
        self,
        _name: &'static str,
        _len: usize,
        visitor: V,
    ) -> DecodeResult<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_seq(visitor)
    }

    fn deserialize_option<V>(self, visitor: V) -> DecodeResult<V::Value>
    where
        V: Visitor<'de>,
    {
        debug!("read_option()");
        match self.pop() {
            Null => visitor.visit_none(),
            value => {
                self.stack.push(value);
                visitor.visit_some(self)
            }
        }
    }

    // In Serde, unit means an anonymous value containing no data.
    fn deserialize_unit<V>(self, visitor: V) -> DecodeResult<V::Value>
    where
        V: Visitor<'de>,
    {
        debug!("read_nil");
        match self.pop() {
            Null => visitor.visit_unit(),
            other => Err(DecodingError(format!("Error decoding Null as {:?}", other))),
        }
    }

    // Unit struct means a named value containing no data.
    fn deserialize_unit_struct<V>(self, _name: &'static str, visitor: V) -> DecodeResult<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_unit(visitor)
    }

    // As is done here, serializers are encouraged to treat newtype structs as
    // insignificant wrappers around the data they contain. That means not
    // parsing anything other than the contained value.
    fn deserialize_newtype_struct<V>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> DecodeResult<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_newtype_struct(self)
    }

    // An identifier in Serde is the type that identifies a field of a struct or
    // the variant of an enum.
    fn deserialize_identifier<V>(self, visitor: V) -> DecodeResult<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_str(visitor)
    }

    fn deserialize_seq<V>(mut self, visitor: V) -> DecodeResult<V::Value>
    where
        V: Visitor<'de>,
    {
        debug!("read_seq()");
        let list = expect!(self.pop(), Array)?;
        let len = list.len();

        for v in list.into_iter().rev() {
            self.stack.push(v);
        }

        let value = visitor.visit_seq(ArrayAccess::new(&mut self, len))?;
        Ok(value)
    }

    // Much like `deserialize_seq` but calls the visitors `visit_map` method
    // with a `MapAccess` implementation, rather than the visitor's `visit_seq`
    // method with a `SeqAccess` implementation.
    fn deserialize_map<V>(mut self, visitor: V) -> DecodeResult<V::Value>
    where
        V: Visitor<'de>,
    {
        debug!("read_map()");
        let obj = expect!(self.pop(), Map)?;
        let len = obj.len();
        for (key, value) in obj.into_iter() {
            self.stack.push(value);
            self.stack.push(String(key));
        }

        let value = visitor.visit_map(MapAccessor::new(&mut self, len * 2))?;
        Ok(value)
    }

    forward_to_deserialize_any! {
        bytes byte_buf char enum i8 i16 ignored_any
    }
}

struct ArrayAccess<'a> {
    de: &'a mut Decoder,
    count: usize,
}

impl<'a> ArrayAccess<'a> {
    fn new(de: &'a mut Decoder, count: usize) -> Self {
        ArrayAccess { de, count }
    }
}

// `SeqAccess` is provided to the `Visitor` to give it the ability to iterate
// through elements of the sequence.
impl<'de, 'a> SeqAccess<'de> for ArrayAccess<'a> {
    type Error = MaxMindDBError;

    fn next_element_seed<T>(&mut self, seed: T) -> DecodeResult<Option<T::Value>>
    where
        T: DeserializeSeed<'de>,
    {
        // Check if there are no more elements.
        if self.count == 0 {
            return Ok(None);
        }
        self.count -= 1;

        // Deserialize an array element.
        seed.deserialize(&mut *self.de).map(Some)
    }
}

struct MapAccessor<'a> {
    de: &'a mut Decoder,
    count: usize,
}

impl<'a> MapAccessor<'a> {
    fn new(de: &'a mut Decoder, count: usize) -> Self {
        MapAccessor { de, count }
    }
}

// `MapAccess` is provided to the `Visitor` to give it the ability to iterate
// through entries of the map.
impl<'de, 'a> MapAccess<'de> for MapAccessor<'a> {
    type Error = MaxMindDBError;

    fn next_key_seed<K>(&mut self, seed: K) -> DecodeResult<Option<K::Value>>
    where
        K: DeserializeSeed<'de>,
    {
        // Check if there are no more entries.
        if self.count == 0 {
            return Ok(None);
        }
        self.count -= 1;

        // Deserialize a map key.
        seed.deserialize(&mut *self.de).map(Some)
    }

    fn next_value_seed<V>(&mut self, seed: V) -> DecodeResult<V::Value>
    where
        V: DeserializeSeed<'de>,
    {
        // Check if there are no more entries.
        if self.count == 0 {
            return Err(DecodingError("no more entries".to_owned()));
        }
        self.count -= 1;

        // Deserialize a map value.
        seed.deserialize(&mut *self.de)
    }
}
