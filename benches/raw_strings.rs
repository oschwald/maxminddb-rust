use maxminddb::deserialize_any_with_raw_strings;
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use std::fmt;
use std::hint::black_box;

/// Walk every value like a language binding, borrowing map keys and raw string
/// bytes. Keep each decoded payload observable before counting it.
pub struct RawStrings(pub usize);

impl<'de> Deserialize<'de> for RawStrings {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_any_with_raw_strings(deserializer, RawVisitor)
    }
}

struct RawKey(usize);

impl<'de> Deserialize<'de> for RawKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer
            .deserialize_identifier(RawVisitor)
            .map(|value| Self(value.0))
    }
}

struct RawVisitor;

impl<'de> Visitor<'de> for RawVisitor {
    type Value = RawStrings;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an MMDB value")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
        black_box(value);
        Ok(RawStrings(1))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
        black_box(value);
        Ok(RawStrings(1))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        black_box(value);
        Ok(RawStrings(1))
    }

    fn visit_u128<E: de::Error>(self, value: u128) -> Result<Self::Value, E> {
        black_box(value);
        Ok(RawStrings(1))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
        black_box(value);
        Ok(RawStrings(1))
    }

    fn visit_borrowed_bytes<E: de::Error>(self, bytes: &'de [u8]) -> Result<Self::Value, E> {
        black_box(bytes);
        Ok(RawStrings(bytes.len()))
    }

    fn visit_newtype_struct<D: Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_bytes(self)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut size = 0;
        while let Some(value) = seq.next_element::<RawStrings>()? {
            size += value.0;
        }
        Ok(RawStrings(size))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut size = 0;
        while let Some(key) = map.next_key::<RawKey>()? {
            size += key.0 + map.next_value::<RawStrings>()?.0;
        }
        Ok(RawStrings(size))
    }
}
