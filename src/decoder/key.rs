//! Reuse the string header resolved while charging a dynamic map key.

use super::{DecodeResult, Decoder, DecoderError};
use serde::de::{Deserializer, Visitor};

pub(super) struct CachedKey<'de> {
    pub bytes: &'de [u8],
    pub continuation: usize,
}

pub(super) struct KeyDeserializer<'a, 'de> {
    pub decoder: &'a mut Decoder<'de>,
    pub cached: Option<CachedKey<'de>>,
}

// Only identifier decoding uses the cached raw bytes. Other Serde entry points
// retain the decoder's type checks, UTF-8 validation, and pointer-depth checks.
macro_rules! delegate {
    ($($method:ident $(($($arg:ident: $ty:ty),*))?;)*) => {
        $(
            #[inline]
            fn $method<V: Visitor<'de>>(self, $($($arg: $ty,)*)? visitor: V) -> DecodeResult<V::Value> {
                self.decoder.$method($($($arg,)*)? visitor)
            }
        )*
    };
}

impl<'de> Deserializer<'de> for KeyDeserializer<'_, 'de> {
    type Error = DecoderError;

    #[inline]
    fn deserialize_identifier<V: Visitor<'de>>(self, visitor: V) -> DecodeResult<V::Value> {
        if let Some(key) = self.cached {
            // The map accessor has already checked and reserved the entire
            // payload. It retains that charge after this visitor returns.
            self.decoder.current_ptr = key.continuation;
            visitor.visit_borrowed_bytes(key.bytes)
        } else {
            self.decoder.deserialize_identifier(visitor)
        }
    }

    fn is_human_readable(&self) -> bool {
        self.decoder.is_human_readable()
    }

    delegate! {
        deserialize_any;
        deserialize_bool;
        deserialize_i8;
        deserialize_i16;
        deserialize_i32;
        deserialize_i64;
        deserialize_i128;
        deserialize_u8;
        deserialize_u16;
        deserialize_u32;
        deserialize_u64;
        deserialize_u128;
        deserialize_f32;
        deserialize_f64;
        deserialize_char;
        deserialize_str;
        deserialize_string;
        deserialize_bytes;
        deserialize_byte_buf;
        deserialize_option;
        deserialize_unit;
        deserialize_unit_struct(name: &'static str);
        deserialize_newtype_struct(name: &'static str);
        deserialize_seq;
        deserialize_tuple(len: usize);
        deserialize_tuple_struct(name: &'static str, len: usize);
        deserialize_map;
        deserialize_struct(name: &'static str, fields: &'static [&'static str]);
        deserialize_enum(name: &'static str, variants: &'static [&'static str]);
        deserialize_ignored_any;
    }
}
