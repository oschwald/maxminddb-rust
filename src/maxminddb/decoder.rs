use log::debug;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::forward_to_deserialize_any;
use serde::serde_if_integer128;
use std::convert::TryInto;

use super::MaxMindDbError;

fn to_usize(base: u8, bytes: &[u8]) -> usize {
    bytes
        .iter()
        .fold(base as usize, |acc, &b| (acc << 8) | b as usize)
}

enum Value<'a, 'de> {
    Any { prev_ptr: usize },
    Bytes(&'de [u8]),
    String(&'de str),
    Bool(bool),
    I32(i32),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    F64(f64),
    F32(f32),
    Map(MapAccessor<'a, 'de>),
    Array(ArrayAccess<'a, 'de>),
}

#[derive(Debug)]
pub struct Decoder<'de> {
    buf: &'de [u8],
    current_ptr: usize,
}

impl<'de> Decoder<'de> {
    pub fn new(buf: &'de [u8], start_ptr: usize) -> Decoder<'de> {
        Decoder {
            buf,
            current_ptr: start_ptr,
        }
    }

    fn eat_byte(&mut self) -> u8 {
        let b = self.buf[self.current_ptr];
        self.current_ptr += 1;
        b
    }

    fn size_from_ctrl_byte(&mut self, ctrl_byte: u8, type_num: u8) -> usize {
        let size = (ctrl_byte & 0x1f) as usize;
        // extended
        if type_num == 0 {
            return size;
        }

        let bytes_to_read = if size > 28 { size - 28 } else { 0 };

        let new_offset = self.current_ptr + bytes_to_read;
        let size_bytes = &self.buf[self.current_ptr..new_offset];
        self.current_ptr = new_offset;

        match size {
            s if s < 29 => s,
            29 => 29_usize + size_bytes[0] as usize,
            30 => 285_usize + to_usize(0, size_bytes),
            _ => 65_821_usize + to_usize(0, size_bytes),
        }
    }

    fn size_and_type(&mut self) -> (usize, u8) {
        let ctrl_byte = self.eat_byte();
        let mut type_num = ctrl_byte >> 5;
        // Extended type
        if type_num == 0 {
            type_num = self.eat_byte() + 7;
        }
        let size = self.size_from_ctrl_byte(ctrl_byte, type_num);
        (size, type_num)
    }

    fn decode_any<V: Visitor<'de>>(&mut self, visitor: V) -> DecodeResult<V::Value> {
        match self.decode_any_value()? {
            Value::Any { prev_ptr } => {
                let res = self.decode_any(visitor);
                self.current_ptr = prev_ptr;
                res
            }
            Value::Bool(x) => visitor.visit_bool(x),
            Value::Bytes(x) => visitor.visit_borrowed_bytes(x),
            Value::String(x) => visitor.visit_borrowed_str(x),
            Value::I32(x) => visitor.visit_i32(x),
            Value::U16(x) => visitor.visit_u16(x),
            Value::U32(x) => visitor.visit_u32(x),
            Value::U64(x) => visitor.visit_u64(x),
            Value::U128(x) => visitor.visit_u128(x),
            Value::F64(x) => visitor.visit_f64(x),
            Value::F32(x) => visitor.visit_f32(x),
            Value::Map(x) => visitor.visit_map(x),
            Value::Array(x) => visitor.visit_seq(x),
        }
    }

    fn decode_any_value(&mut self) -> DecodeResult<Value<'_, 'de>> {
        let (size, type_num) = self.size_and_type();

        Ok(match type_num {
            1 => {
                let new_ptr = self.decode_pointer(size);
                let prev_ptr = self.current_ptr;
                self.current_ptr = new_ptr;

                Value::Any { prev_ptr }
            }
            2 => Value::String(self.decode_string(size)?),
            3 => Value::F64(self.decode_double(size)?),
            4 => Value::Bytes(self.decode_bytes(size)?),
            5 => Value::U16(self.decode_uint16(size)?),
            6 => Value::U32(self.decode_uint32(size)?),
            7 => self.decode_map(size),
            8 => Value::I32(self.decode_int(size)?),
            9 => Value::U64(self.decode_uint64(size)?),
            10 => {
                serde_if_integer128! {
                    return Ok(Value::U128(self.decode_uint128(size)?));
                }

                #[allow(unreachable_code)]
                Value::Bytes(self.decode_bytes(size)?)
            }
            11 => self.decode_array(size),
            14 => Value::Bool(self.decode_bool(size)?),
            15 => Value::F32(self.decode_float(size)?),
            u => {
                return Err(MaxMindDbError::InvalidDatabase(format!(
                    "Unknown data type: {u:?}"
                )))
            }
        })
    }

    fn decode_array(&mut self, size: usize) -> Value<'_, 'de> {
        Value::Array(ArrayAccess {
            de: self,
            count: size,
        })
    }

    fn decode_bool(&mut self, size: usize) -> DecodeResult<bool> {
        match size {
            0 | 1 => Ok(size != 0),
            s => Err(MaxMindDbError::InvalidDatabase(format!(
                "bool of size {s:?}"
            ))),
        }
    }

    fn decode_bytes(&mut self, size: usize) -> DecodeResult<&'de [u8]> {
        let new_offset = self.current_ptr + size;
        let u8_slice = &self.buf[self.current_ptr..new_offset];
        self.current_ptr = new_offset;

        Ok(u8_slice)
    }

    fn decode_float(&mut self, size: usize) -> DecodeResult<f32> {
        let new_offset = self.current_ptr + size;
        let value: [u8; 4] = self.buf[self.current_ptr..new_offset]
            .try_into()
            .map_err(|_| {
                MaxMindDbError::InvalidDatabase(format!(
                    "float of size {:?}",
                    new_offset - self.current_ptr
                ))
            })?;
        self.current_ptr = new_offset;
        let float_value = f32::from_be_bytes(value);
        Ok(float_value)
    }

    fn decode_double(&mut self, size: usize) -> DecodeResult<f64> {
        let new_offset = self.current_ptr + size;
        let value: [u8; 8] = self.buf[self.current_ptr..new_offset]
            .try_into()
            .map_err(|_| {
                MaxMindDbError::InvalidDatabase(format!(
                    "double of size {:?}",
                    new_offset - self.current_ptr
                ))
            })?;
        self.current_ptr = new_offset;
        let float_value = f64::from_be_bytes(value);
        Ok(float_value)
    }

    fn decode_uint64(&mut self, size: usize) -> DecodeResult<u64> {
        match size {
            s if s <= 8 => {
                let new_offset = self.current_ptr + size;

                let value = self.buf[self.current_ptr..new_offset]
                    .iter()
                    .fold(0_u64, |acc, &b| (acc << 8) | u64::from(b));
                self.current_ptr = new_offset;
                Ok(value)
            }
            s => Err(MaxMindDbError::InvalidDatabase(format!(
                "u64 of size {s:?}"
            ))),
        }
    }

    serde_if_integer128! {
        fn decode_uint128(
            &mut self,
            size: usize,
        ) -> DecodeResult<u128> {
            match size {
                s if s <= 16 => {
                    let new_offset = self.current_ptr + size;

                    let value = self.buf[self.current_ptr..new_offset]
                        .iter()
                        .fold(0_u128, |acc, &b| (acc << 8) | u128::from(b));
                    self.current_ptr = new_offset;
                    Ok(value)
                }
                s => Err(MaxMindDbError::InvalidDatabase(format!(
                    "u128 of size {s:?}"
                ))),
            }
        }
    }

    fn decode_uint32(&mut self, size: usize) -> DecodeResult<u32> {
        match size {
            s if s <= 4 => {
                let new_offset = self.current_ptr + size;

                let value = self.buf[self.current_ptr..new_offset]
                    .iter()
                    .fold(0_u32, |acc, &b| (acc << 8) | u32::from(b));
                self.current_ptr = new_offset;
                Ok(value)
            }
            s => Err(MaxMindDbError::InvalidDatabase(format!(
                "u32 of size {s:?}"
            ))),
        }
    }

    fn decode_uint16(&mut self, size: usize) -> DecodeResult<u16> {
        match size {
            s if s <= 2 => {
                let new_offset = self.current_ptr + size;

                let value = self.buf[self.current_ptr..new_offset]
                    .iter()
                    .fold(0_u16, |acc, &b| (acc << 8) | u16::from(b));
                self.current_ptr = new_offset;
                Ok(value)
            }
            s => Err(MaxMindDbError::InvalidDatabase(format!(
                "u16 of size {s:?}"
            ))),
        }
    }

    fn decode_int(&mut self, size: usize) -> DecodeResult<i32> {
        match size {
            s if s <= 4 => {
                let new_offset = self.current_ptr + size;

                let value = self.buf[self.current_ptr..new_offset]
                    .iter()
                    .fold(0_i32, |acc, &b| (acc << 8) | i32::from(b));
                self.current_ptr = new_offset;
                Ok(value)
            }
            s => Err(MaxMindDbError::InvalidDatabase(format!(
                "int32 of size {s:?}"
            ))),
        }
    }

    fn decode_map(&mut self, size: usize) -> Value<'_, 'de> {
        Value::Map(MapAccessor {
            de: self,
            count: size * 2,
        })
    }

    fn decode_pointer(&mut self, size: usize) -> usize {
        let pointer_value_offset = [0, 0, 2048, 526_336, 0];
        let pointer_size = ((size >> 3) & 0x3) + 1;
        let new_offset = self.current_ptr + pointer_size;
        let pointer_bytes = &self.buf[self.current_ptr..new_offset];
        self.current_ptr = new_offset;

        let base = if pointer_size == 4 {
            0
        } else {
            (size & 0x7) as u8
        };
        let unpacked = to_usize(base, pointer_bytes);

        unpacked + pointer_value_offset[pointer_size]
    }

    #[cfg(feature = "unsafe-str-decode")]
    fn decode_string(&mut self, size: usize) -> DecodeResult<&'de str> {
        use std::str::from_utf8_unchecked;

        let new_offset: usize = self.current_ptr + size;
        let bytes = &self.buf[self.current_ptr..new_offset];
        self.current_ptr = new_offset;
        // SAFETY:
        // A corrupt maxminddb will cause undefined behaviour.
        // If the caller has verified the integrity of their database and trusts their upstream
        // provider, they can opt-into the performance gains provided by this unsafe function via
        // the `unsafe-str-decode` feature flag.
        // This can provide around 20% performance increase in the lookup benchmark.
        let v = unsafe { from_utf8_unchecked(bytes) };
        Ok(v)
    }

    #[cfg(not(feature = "unsafe-str-decode"))]
    fn decode_string(&mut self, size: usize) -> DecodeResult<&'de str> {
        #[cfg(feature = "simdutf8")]
        use simdutf8::basic::from_utf8;
        #[cfg(not(feature = "simdutf8"))]
        use std::str::from_utf8;

        let new_offset: usize = self.current_ptr + size;
        let bytes = &self.buf[self.current_ptr..new_offset];
        self.current_ptr = new_offset;
        match from_utf8(bytes) {
            Ok(v) => Ok(v),
            Err(_) => Err(MaxMindDbError::InvalidDatabase(
                "error decoding string".to_owned(),
            )),
        }
    }
}

pub type DecodeResult<T> = Result<T, MaxMindDbError>;

impl<'de: 'a, 'a> de::Deserializer<'de> for &'a mut Decoder<'de> {
    type Error = MaxMindDbError;

    fn deserialize_any<V>(self, visitor: V) -> DecodeResult<V::Value>
    where
        V: Visitor<'de>,
    {
        debug!("deserialize_any");

        self.decode_any(visitor)
    }

    fn deserialize_option<V>(self, visitor: V) -> DecodeResult<V::Value>
    where
        V: Visitor<'de>,
    {
        debug!("deserialize_option");

        visitor.visit_some(self)
    }

    forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf unit unit_struct newtype_struct seq tuple
        tuple_struct map struct enum identifier ignored_any
    }
}

struct ArrayAccess<'a, 'de: 'a> {
    de: &'a mut Decoder<'de>,
    count: usize,
}

// `SeqAccess` is provided to the `Visitor` to give it the ability to iterate
// through elements of the sequence.
impl<'de> SeqAccess<'de> for ArrayAccess<'_, 'de> {
    type Error = MaxMindDbError;

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

struct MapAccessor<'a, 'de: 'a> {
    de: &'a mut Decoder<'de>,
    count: usize,
}

// `MapAccess` is provided to the `Visitor` to give it the ability to iterate
// through entries of the map.
impl<'de> MapAccess<'de> for MapAccessor<'_, 'de> {
    type Error = MaxMindDbError;

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
            return Err(MaxMindDbError::Decoding("no more entries".to_owned()));
        }
        self.count -= 1;

        // Deserialize a map value.
        seed.deserialize(&mut *self.de)
    }
}
