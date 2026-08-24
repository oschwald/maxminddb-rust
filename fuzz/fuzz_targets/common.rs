use std::fmt;

use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;

pub(crate) struct FuzzValue;

impl<'de> Deserialize<'de> for FuzzValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(FuzzValueVisitor)
    }
}

struct FuzzValueVisitor;

impl<'de> Visitor<'de> for FuzzValueVisitor {
    type Value = FuzzValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a MaxMind DB value")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(FuzzValue)
    }

    fn visit_i32<E>(self, _value: i32) -> Result<Self::Value, E> {
        Ok(FuzzValue)
    }

    fn visit_u16<E>(self, _value: u16) -> Result<Self::Value, E> {
        Ok(FuzzValue)
    }

    fn visit_u32<E>(self, _value: u32) -> Result<Self::Value, E> {
        Ok(FuzzValue)
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(FuzzValue)
    }

    fn visit_u128<E>(self, _value: u128) -> Result<Self::Value, E> {
        Ok(FuzzValue)
    }

    fn visit_f32<E>(self, _value: f32) -> Result<Self::Value, E> {
        Ok(FuzzValue)
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(FuzzValue)
    }

    fn visit_borrowed_str<E>(self, _value: &'de str) -> Result<Self::Value, E> {
        Ok(FuzzValue)
    }

    fn visit_borrowed_bytes<E>(self, _value: &'de [u8]) -> Result<Self::Value, E> {
        Ok(FuzzValue)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element::<FuzzValue>()?.is_some() {}
        Ok(FuzzValue)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        while map.next_key::<FuzzIdentifier>()?.is_some() {
            map.next_value::<FuzzValue>()?;
        }
        Ok(FuzzValue)
    }
}

struct FuzzIdentifier;

impl<'de> Deserialize<'de> for FuzzIdentifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_identifier(FuzzIdentifierVisitor)
    }
}

struct FuzzIdentifierVisitor;

impl<'de> Visitor<'de> for FuzzIdentifierVisitor {
    type Value = FuzzIdentifier;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a MaxMind DB map key")
    }

    fn visit_borrowed_str<E>(self, _value: &'de str) -> Result<Self::Value, E> {
        Ok(FuzzIdentifier)
    }

    fn visit_borrowed_bytes<E>(self, _value: &'de [u8]) -> Result<Self::Value, E> {
        Ok(FuzzIdentifier)
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(FuzzIdentifier)
    }

    fn visit_bytes<E>(self, _value: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(FuzzIdentifier)
    }
}
