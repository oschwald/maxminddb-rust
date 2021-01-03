use log::debug;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::forward_to_deserialize_any;
use serde::serde_if_integer128;

use super::MaxMindDBError;
use super::MaxMindDBError::DecodingError;

fn to_usize(base: u8, bytes: &[u8]) -> usize {
    bytes
        .iter()
        .fold(base as usize, |acc, &b| (acc << 8) | b as usize)
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
            29 => 29usize + size_bytes[0] as usize,
            30 => 285usize + to_usize(0, size_bytes),
            _ => 65_821usize + to_usize(0, size_bytes),
        }
    }

    fn decode_any<V: Visitor<'de>>(&mut self, visitor: V) -> DecodeResult<V::Value> {
        let ctrl_byte = self.eat_byte();
        let mut type_num = ctrl_byte >> 5;
        // Extended type
        if type_num == 0 {
            type_num = self.eat_byte() + 7;
        }
        let size = self.size_from_ctrl_byte(ctrl_byte, type_num);

        match type_num {
            1 => {
                let new_ptr = self.decode_pointer(size);
                let prev_ptr = self.current_ptr;
                self.current_ptr = new_ptr;

                let res = self.decode_any(visitor);
                self.current_ptr = prev_ptr;
                res
            }
            2 => self.decode_string(visitor, size),
            3 => self.decode_double(visitor, size),
            4 => self.decode_bytes(visitor, size),
            5 => self.decode_uint16(visitor, size),
            6 => self.decode_uint32(visitor, size),
            7 => self.decode_map(visitor, size),
            8 => self.decode_int(visitor, size),
            9 => self.decode_uint64(visitor, size),
            10 => {
                serde_if_integer128! {
                    return self.decode_uint128(visitor, size);
                }

                #[allow(unreachable_code)]
                self.decode_bytes(visitor, size)
            }
            11 => self.decode_array(visitor, size),
            14 => self.decode_bool(visitor, size),
            15 => self.decode_float(visitor, size),
            u => Err(MaxMindDBError::InvalidDatabaseError(format!(
                "Unknown data type: {:?}",
                u
            ))),
        }
    }

    fn decode_array<V: Visitor<'de>>(&mut self, visitor: V, size: usize) -> DecodeResult<V::Value> {
        visitor.visit_seq(ArrayAccess {
            de: self,
            count: size,
        })
    }

    fn decode_bool<V: Visitor<'de>>(&mut self, visitor: V, size: usize) -> DecodeResult<V::Value> {
        match size {
            0 | 1 => visitor.visit_bool(size != 0),
            s => Err(MaxMindDBError::InvalidDatabaseError(format!(
                "bool of size {:?}",
                s
            ))),
        }
    }

    fn decode_bytes<V: Visitor<'de>>(&mut self, visitor: V, size: usize) -> DecodeResult<V::Value> {
        let new_offset = self.current_ptr + size;
        let u8_slice = &self.buf[self.current_ptr..new_offset];
        self.current_ptr = new_offset;

        visitor.visit_borrowed_bytes(u8_slice)
    }

    fn decode_float<V: Visitor<'de>>(&mut self, visitor: V, size: usize) -> DecodeResult<V::Value> {
        match size {
            4 => {
                let new_offset = self.current_ptr + size;
                let value = self.buf[self.current_ptr..new_offset]
                    .iter()
                    .fold(0u32, |acc, &b| (acc << 8) | u32::from(b));
                self.current_ptr = new_offset;

                let float_value = f32::from_bits(value);
                visitor.visit_f32(float_value)
            }
            s => Err(MaxMindDBError::InvalidDatabaseError(format!(
                "float of size {:?}",
                s
            ))),
        }
    }

    fn decode_double<V: Visitor<'de>>(
        &mut self,
        visitor: V,
        size: usize,
    ) -> DecodeResult<V::Value> {
        match size {
            8 => {
                let new_offset = self.current_ptr + size;
                let value = self.buf[self.current_ptr..new_offset]
                    .iter()
                    .fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
                self.current_ptr = new_offset;

                let float_value = f64::from_bits(value);
                visitor.visit_f64(float_value)
            }
            s => Err(MaxMindDBError::InvalidDatabaseError(format!(
                "double of size {:?}",
                s
            ))),
        }
    }

    fn decode_uint64<V: Visitor<'de>>(
        &mut self,
        visitor: V,
        size: usize,
    ) -> DecodeResult<V::Value> {
        match size {
            s if s <= 8 => {
                let new_offset = self.current_ptr + size;

                let value = self.buf[self.current_ptr..new_offset]
                    .iter()
                    .fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
                self.current_ptr = new_offset;
                visitor.visit_u64(value)
            }
            s => Err(MaxMindDBError::InvalidDatabaseError(format!(
                "u64 of size {:?}",
                s
            ))),
        }
    }

    serde_if_integer128! {
        fn decode_uint128<V: Visitor<'de>>(
            &mut self,
            visitor: V,
            size: usize,
        ) -> DecodeResult<V::Value> {
            match size {
                s if s <= 16 => {
                    let new_offset = self.current_ptr + size;

                    let value = self.buf[self.current_ptr..new_offset]
                        .iter()
                        .fold(0u128, |acc, &b| (acc << 8) | u128::from(b));
                    self.current_ptr = new_offset;
                    visitor.visit_u128(value)
                }
                s => Err(MaxMindDBError::InvalidDatabaseError(format!(
                    "u128 of size {:?}",
                    s
                ))),
            }
        }
    }

    fn decode_uint32<V: Visitor<'de>>(
        &mut self,
        visitor: V,
        size: usize,
    ) -> DecodeResult<V::Value> {
        match size {
            s if s <= 4 => {
                let new_offset = self.current_ptr + size;

                let value = self.buf[self.current_ptr..new_offset]
                    .iter()
                    .fold(0u32, |acc, &b| (acc << 8) | u32::from(b));
                self.current_ptr = new_offset;
                visitor.visit_u32(value)
            }
            s => Err(MaxMindDBError::InvalidDatabaseError(format!(
                "u32 of size {:?}",
                s
            ))),
        }
    }

    fn decode_uint16<V: Visitor<'de>>(
        &mut self,
        visitor: V,
        size: usize,
    ) -> DecodeResult<V::Value> {
        match size {
            s if s <= 2 => {
                let new_offset = self.current_ptr + size;

                let value = self.buf[self.current_ptr..new_offset]
                    .iter()
                    .fold(0u16, |acc, &b| (acc << 8) | u16::from(b));
                self.current_ptr = new_offset;
                visitor.visit_u16(value)
            }
            s => Err(MaxMindDBError::InvalidDatabaseError(format!(
                "u16 of size {:?}",
                s
            ))),
        }
    }

    fn decode_int<V: Visitor<'de>>(&mut self, visitor: V, size: usize) -> DecodeResult<V::Value> {
        match size {
            s if s <= 4 => {
                let new_offset = self.current_ptr + size;

                let value = self.buf[self.current_ptr..new_offset]
                    .iter()
                    .fold(0i32, |acc, &b| (acc << 8) | i32::from(b));
                self.current_ptr = new_offset;
                visitor.visit_i32(value)
            }
            s => Err(MaxMindDBError::InvalidDatabaseError(format!(
                "int32 of size {:?}",
                s
            ))),
        }
    }

    fn decode_map<V: Visitor<'de>>(&mut self, visitor: V, size: usize) -> DecodeResult<V::Value> {
        visitor.visit_map(MapAccessor {
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
    fn decode_string<V: Visitor<'de>>(
        &mut self,
        visitor: V,
        size: usize,
    ) -> DecodeResult<V::Value> {
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
        visitor.visit_borrowed_str(v)
    }

    #[cfg(not(feature = "unsafe-str-decode"))]
    fn decode_string<V: Visitor<'de>>(
        &mut self,
        visitor: V,
        size: usize,
    ) -> DecodeResult<V::Value> {
        use std::str::from_utf8;

        let new_offset: usize = self.current_ptr + size;
        let bytes = &self.buf[self.current_ptr..new_offset];
        self.current_ptr = new_offset;
        match from_utf8(bytes) {
            Ok(v) => visitor.visit_borrowed_str(v),
            Err(_) => Err(MaxMindDBError::InvalidDatabaseError(
                "error decoding string".to_owned(),
            )),
        }
    }
}

pub type DecodeResult<T> = Result<T, MaxMindDBError>;

impl<'de: 'a, 'a> de::Deserializer<'de> for &'a mut Decoder<'de> {
    type Error = MaxMindDBError;

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
impl<'de, 'a> SeqAccess<'de> for ArrayAccess<'a, 'de> {
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

struct MapAccessor<'a, 'de: 'a> {
    de: &'a mut Decoder<'de>,
    count: usize,
}

// `MapAccess` is provided to the `Visitor` to give it the ability to iterate
// through entries of the map.
impl<'de, 'a> MapAccess<'de> for MapAccessor<'a, 'de> {
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
