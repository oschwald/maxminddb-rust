//! Binary format decoder for MaxMind DB files.
//!
//! This module implements deserialization of the MaxMind DB binary format
//! into Rust types via serde. The decoder handles all MaxMind DB data types
//! including pointers, maps, arrays, and primitive types.
//!
//! Most users should not need to interact with this module directly.
//! Use [`Reader::lookup()`](crate::Reader::lookup) for normal lookups.

use serde::de::{
    self, value::BorrowedBytesDeserializer, DeserializeSeed, Deserializer, MapAccess, SeqAccess,
    Visitor,
};
use serde::forward_to_deserialize_any;

use std::fmt;

use crate::error::MaxMindDbError;

mod key;
mod verification;
use key::{CachedKey, KeyDeserializer};
pub(crate) use verification::VerificationState;

// MaxMind DB type constants
const TYPE_EXTENDED: usize = 0;
pub(crate) const TYPE_POINTER: usize = 1;
const TYPE_STRING: usize = 2;
const TYPE_DOUBLE: usize = 3;
const TYPE_BYTES: usize = 4;
const TYPE_UINT16: usize = 5;
const TYPE_UINT32: usize = 6;
pub(crate) const TYPE_MAP: usize = 7;
const TYPE_INT32: usize = 8;
const TYPE_UINT64: usize = 9;
const TYPE_UINT128: usize = 10;
pub(crate) const TYPE_ARRAY: usize = 11;
const TYPE_BOOL: usize = 14;
const TYPE_FLOAT: usize = 15;

const RAW_STRINGS_NEWTYPE: &str = "$maxminddb::raw_strings";

/// Maximum recursion depth for nested data structures.
/// This matches the value used in libmaxminddb and the Go reader.
///
/// Decoding recurses once per level. An unoptimized build gives every local
/// of an inlined callee its own stack slot, so the `inline(always)` header
/// and scalar helpers made each level take about 5 KiB there, and 512 levels
/// overflowed a 2 MiB thread stack. Builds with debug assertions mark three of
/// them only `#[inline]`: the header reader, the pointer decoder, and the
/// dynamic value decoder. An unoptimized build does not inline a hint, and an
/// optimized one with debug assertions, such as a fuzz build, still may. Rust
/// has no `cfg` for the optimization level, and debug assertions are on in
/// Cargo's unoptimized profiles and off in its optimized ones, so release
/// builds still force the inlining.
const MAXIMUM_DATA_STRUCTURE_DEPTH: u16 = 512;

/// Maximum number of logical values decoded in one container-shaped operation.
/// A container reserves all of its children before the visitor enters it, so a
/// pointer fan-out exhausts the budget without a counter update on every scalar
/// header. A pointer and the value it resolves to are one logical occurrence.
const MAXIMUM_DATA_STRUCTURE_VALUES: u32 = 1 << 16;

/// Maximum total string and bytes payload delivered through budgeted decode
/// paths. Re-decoding a shared target recharges its payload. Payload reached
/// only through `skip_value`, including an unknown or `IgnoredAny` value, is not
/// materialized or charged. Keys exposed to a dynamically shaped map visitor
/// are conservatively precharged before the visitor's key seed runs, even when
/// that seed ignores them.
const MAXIMUM_DATA_STRUCTURE_BYTES: usize = 2 << 20;

/// Identifier bytes covered by the logical-value budget rather than the
/// payload counter. At most one identifier occurs per reserved logical value,
/// so this allowance can add no more than another 2 MiB per operation while
/// keeping ordinary short schema keys off the payload-accounting hot path.
const MAXIMUM_UNCHARGED_IDENTIFIER_BYTES: usize =
    MAXIMUM_DATA_STRUCTURE_BYTES / MAXIMUM_DATA_STRUCTURE_VALUES as usize;

// Depth, the logical-value count, and the budget flags share one word,
// preserving Decoder's existing size on 64-bit targets. Keeping the payload
// allowance separate avoids extracting and replacing it for every string.
const DEPTH_MASK: u32 = (1 << 10) - 1;
const BUDGET_VALUES_SHIFT: u32 = 10;
const BUDGET_VALUES_MASK: u32 = ((1 << 17) - 1) << BUDGET_VALUES_SHIFT;
const BUDGET_ACTIVE_MASK: u32 = 1 << 27;
/// Makes the typed numeric entry points that have their own MMDB type accept
/// only that type. The spec fixes the type of each metadata field, so
/// metadata is decoded with exact types.
const EXACT_SCALARS_MASK: u32 = 1 << 28;

/// Lower limit for values skipped through unknown fields or IgnoredAny.
/// Skipping is recursive and can be reached by corrupt data that callers did
/// not explicitly request, so keep the limit below small default thread stacks.
const MAXIMUM_SKIPPED_DATA_STRUCTURE_DEPTH: u16 = 128;

#[cfg(not(feature = "unsafe-str-decode"))]
#[inline]
fn is_ascii(bytes: &[u8]) -> bool {
    // Overlapping word reads cover short strings without a byte-by-byte tail.
    match bytes.len() {
        4..=7 => {
            let first = u32::from_ne_bytes(bytes[..4].try_into().unwrap());
            let last = u32::from_ne_bytes(bytes[bytes.len() - 4..].try_into().unwrap());
            (first | last) & 0x8080_8080 == 0
        }
        8..=16 => {
            let first = u64::from_ne_bytes(bytes[..8].try_into().unwrap());
            let last = u64::from_ne_bytes(bytes[bytes.len() - 8..].try_into().unwrap());
            (first | last) & 0x8080_8080_8080_8080 == 0
        }
        _ => bytes.is_ascii(),
    }
}

macro_rules! decode_int_like {
    ($name:ident, $ty:ty, $max_size:expr, $label:literal, $zero:expr) => {
        fn $name(&mut self, size: usize) -> DecodeResult<$ty> {
            match size {
                s if s <= $max_size => {
                    let new_offset = self
                        .current_ptr
                        .checked_add(size)
                        .filter(|&offset| offset <= self.limit)
                        .ok_or_else(|| {
                            self.invalid_db_error(&format!("{} of size {}", $label, size))
                        })?;
                    let value = self
                        .slice(self.current_ptr, new_offset)
                        .iter()
                        .fold($zero, |acc, &b| (acc << 8) | <$ty>::from(b));
                    self.current_ptr = new_offset;
                    Ok(value)
                }
                s => Err(self.invalid_db_error(&format!("{} of size {}", $label, s))),
            }
        }
    };
}

macro_rules! deserialize_direct_scalar {
    ($name:ident, $expected_type:expr, $label:literal, $visit:ident, $decode:ident) => {
        fn $name<V>(self, visitor: V) -> DecodeResult<V::Value>
        where
            V: Visitor<'de>,
        {
            let (size, type_num) = self.size_and_type()?;
            self.decode_direct(size, type_num, $expected_type, $label, |de, size| {
                visitor.$visit(de.$decode(size)?)
            })
        }
    };
}

/// Like `deserialize_direct_scalar!`, but also accepts one narrower MMDB type
/// and widens it losslessly with `From`, unless the decoder was created with
/// `new_exact_scalars`. The widening path is cold so values
/// stored as the requested type decode exactly as before. Integer types use
/// `deserialize_integer!` instead, which converts by value.
macro_rules! deserialize_widening_scalar {
    (
        $name:ident,
        $expected_type:expr,
        $label:literal,
        $visit:ident,
        $decode:ident,
        $ty:ty,
        $narrow_type:expr => $narrow_decode:ident
    ) => {
        fn $name<V>(self, visitor: V) -> DecodeResult<V::Value>
        where
            V: Visitor<'de>,
        {
            #[cold]
            #[inline(never)]
            fn widen<'de, V>(
                de: &mut Decoder<'de>,
                size: usize,
                type_num: usize,
                visitor: V,
            ) -> DecodeResult<V::Value>
            where
                V: Visitor<'de>,
            {
                if de.state & EXACT_SCALARS_MASK != 0 {
                    return Err(de.type_mismatch($label, type_num));
                }
                if type_num != $narrow_type {
                    return Err(de.type_mismatch($label, type_num));
                }
                let offset = de.current_ptr;
                visitor
                    .$visit(<$ty>::from(de.$narrow_decode(size)?))
                    .map_err(|err| with_decoding_offset(err, offset))
            }

            let (size, type_num) = self.size_and_type()?;
            self.decode_direct_or(
                size,
                type_num,
                $expected_type,
                visitor,
                |de, size, visitor| visitor.$visit(de.$decode(size)?),
                widen,
            )
        }
    };
}

/// Gives a decoding error from a visitor the offset of the value it rejected,
/// as a type mismatch at the same place would report.
#[cold]
fn with_decoding_offset(mut err: DecoderError, offset: usize) -> DecoderError {
    if let MaxMindDbError::Decoding { offset: o, .. } = &mut *err {
        o.get_or_insert(offset);
    }
    err
}

/// Rust integer types that have their own MMDB type. The matching type is
/// decoded on the hot path. Any other MMDB integer goes to a cold path that
/// accepts it when its value fits; see [`Decoder::decode_integer`].
macro_rules! deserialize_integer {
    ($name:ident, $expected_type:expr, $label:literal, $visit:ident, $decode:ident, $ty:ty) => {
        fn $name<V>(self, visitor: V) -> DecodeResult<V::Value>
        where
            V: Visitor<'de>,
        {
            #[cold]
            #[inline(never)]
            fn convert<'de, V>(
                de: &mut Decoder<'de>,
                size: usize,
                type_num: usize,
                visitor: V,
            ) -> DecodeResult<V::Value>
            where
                V: Visitor<'de>,
            {
                if de.state & EXACT_SCALARS_MASK != 0 {
                    return Err(de.type_mismatch($label, type_num));
                }
                de.decode_integer::<$ty, V>(size, type_num, $label, visitor)
            }

            let (size, type_num) = self.size_and_type()?;
            self.decode_direct_or(
                size,
                type_num,
                $expected_type,
                visitor,
                |de, size, visitor| visitor.$visit(de.$decode(size)?),
                convert,
            )
        }
    };
}

/// Rust integer types without an MMDB type of their own. They decode like
/// `deserialize_any`, so a stored integer reaches the visitor method for its
/// stored type and Serde's visitor checks its range, except that a uint128
/// value that fits in a `u64` reaches `visit_u64`; see [`U128Visitor`].
macro_rules! deserialize_integer_any {
    ($($name:ident),+ $(,)?) => {
        $(fn $name<V>(self, visitor: V) -> DecodeResult<V::Value>
        where
            V: Visitor<'de>,
        {
            self.decode_any(U128Visitor(visitor))
        })+
    };
}

/// A Rust integer type with its own MMDB type, which typed decoding converts
/// other MMDB integers into.
trait IntegerTarget:
    Sized + TryFrom<u16> + TryFrom<u32> + TryFrom<u64> + TryFrom<u128> + TryFrom<i32>
{
    /// Calls the visitor method for this type.
    fn visit<'de, V, E>(self, visitor: V) -> Result<V::Value, E>
    where
        V: Visitor<'de>,
        E: de::Error;
}

macro_rules! integer_targets {
    ($($ty:ty => $visit:ident),+ $(,)?) => {
        $(impl IntegerTarget for $ty {
            #[inline]
            fn visit<'de, V, E>(self, visitor: V) -> Result<V::Value, E>
            where
                V: Visitor<'de>,
                E: de::Error,
            {
                visitor.$visit(self)
            }
        })+
    };
}

integer_targets!(
    u16 => visit_u16,
    u32 => visit_u32,
    u64 => visit_u64,
    u128 => visit_u128,
    i32 => visit_i32,
);

/// Passes a stored MMDB integer to a visitor that asked for `T`. A value that
/// fits in `T` goes to the visitor method for `T`. A value that does not fit
/// goes to `visit_stored`, the visitor method for its stored type, as
/// `deserialize_any` would pass it. Serde's integer visitors then reject it
/// with their usual out-of-range error, or clamp it for `Saturating`, except
/// that Serde's visitors narrower than 128 bits reject any `visit_u128`. The
/// uint128 caller passes a value that fits in a `u64` to `visit_u64` instead,
/// as [`U128Visitor`] does.
#[inline]
fn visit_integer<'de, T, S, V, E>(
    value: S,
    visitor: V,
    visit_stored: impl FnOnce(V, S) -> Result<V::Value, E>,
) -> Result<V::Value, E>
where
    T: IntegerTarget + TryFrom<S>,
    S: Copy,
    V: Visitor<'de>,
    E: de::Error,
{
    match T::try_from(value) {
        Ok(value) => value.visit(visitor),
        Err(_) => visit_stored(visitor, value),
    }
}

/// Wraps the visitor of a Rust integer type that has no MMDB type of its own.
/// A uint128 value that fits in a `u64` goes to `visit_u64`, because Serde's
/// narrower integer visitors reject `visit_u128` whatever the value. Every
/// other value reaches the wrapped visitor unchanged, as `deserialize_any`
/// would pass it.
struct U128Visitor<V>(V);

macro_rules! forward_visits {
    ($($visit:ident: $ty:ty),+ $(,)?) => {
        $(fn $visit<E>(self, v: $ty) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.0.$visit(v)
        })+
    };
}

impl<'de, V> Visitor<'de> for U128Visitor<V>
where
    V: Visitor<'de>,
{
    type Value = V::Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.expecting(formatter)
    }

    fn visit_u128<E>(self, v: u128) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        match u64::try_from(v) {
            Ok(v) => self.0.visit_u64(v),
            Err(_) => self.0.visit_u128(v),
        }
    }

    forward_visits!(
        visit_bool: bool,
        visit_i8: i8,
        visit_i16: i16,
        visit_i32: i32,
        visit_i64: i64,
        visit_i128: i128,
        visit_u8: u8,
        visit_u16: u16,
        visit_u32: u32,
        visit_u64: u64,
        visit_f32: f32,
        visit_f64: f64,
        visit_char: char,
        visit_str: &str,
        visit_borrowed_str: &'de str,
        visit_string: String,
        visit_bytes: &[u8],
        visit_borrowed_bytes: &'de [u8],
        visit_byte_buf: Vec<u8>,
    );

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.0.visit_none()
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        self.0.visit_some(deserializer)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.0.visit_unit()
    }

    fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        self.0.visit_newtype_struct(deserializer)
    }

    fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        self.0.visit_seq(seq)
    }

    fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        self.0.visit_map(map)
    }

    fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
    where
        A: de::EnumAccess<'de>,
    {
        self.0.visit_enum(data)
    }
}

macro_rules! deserialize_direct_payload {
    ($name:ident, $expected_type:expr, $label:literal, $visit:ident, $decode:ident) => {
        #[cfg_attr(feature = "unsafe-str-decode", inline(always))]
        fn $name<V>(self, visitor: V) -> DecodeResult<V::Value>
        where
            V: Visitor<'de>,
        {
            let (size, type_num) = self.size_and_type()?;
            self.decode_direct(size, type_num, $expected_type, $label, |de, size| {
                de.count_payload(size)?;
                visitor.$visit(de.$decode(size)?)
            })
        }
    };
}

enum Value<'a, 'de> {
    Any { prev_ptr: usize },
    Bytes(&'de [u8]),
    String(&'de str),
    RawString(&'de [u8]),
    Bool(bool),
    I32(i32),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    F64(f64),
    F32(f32),
    Map(MapAccessor<'a, 'de, true>),
    Array(ArrayAccess<'a, 'de>),
}

/// Decoder for MaxMind DB binary format.
///
/// Implements serde's `Deserializer` trait. Handles pointer resolution,
/// type coercion, and nested data structures.
#[derive(Debug)]
pub(crate) struct Decoder<'de> {
    buf: &'de [u8],
    limit: usize,
    current_ptr: usize,
    state: u32,
    payload_remaining: u32,
}

impl<'de> Decoder<'de> {
    /// Creates a decoder over all of `buf`.
    ///
    /// `slice` and `eat_byte` use unchecked reads that rely on
    /// `limit <= buf.len()`. Taking the limit from `buf` itself keeps that
    /// invariant true without a separate check.
    pub(crate) fn new(buf: &'de [u8], start_ptr: usize) -> Decoder<'de> {
        Decoder {
            buf,
            limit: buf.len(),
            current_ptr: start_ptr,
            state: 0,
            payload_remaining: MAXIMUM_DATA_STRUCTURE_BYTES as u32,
        }
    }

    /// Creates a decoder whose typed numeric entry points with their own MMDB
    /// type (`u16`, `u32`, `u64`, `u128`, `i32` and `f64`) accept only that
    /// type, as metadata decoding requires.
    pub(crate) fn new_exact_scalars(buf: &'de [u8], start_ptr: usize) -> Decoder<'de> {
        let mut decoder = Decoder::new(buf, start_ptr);
        decoder.state |= EXACT_SCALARS_MASK;
        decoder
    }

    /// Creates a decoder that reads no further than `limit`.
    ///
    /// # Panics
    ///
    /// Panics if `limit > buf.len()`.
    #[cfg(test)]
    pub(crate) fn new_with_limit(buf: &'de [u8], start_ptr: usize, limit: usize) -> Decoder<'de> {
        assert!(
            limit <= buf.len(),
            "decoder limit {limit} exceeds buffer length {}",
            buf.len()
        );
        Decoder {
            limit,
            ..Decoder::new(buf, start_ptr)
        }
    }

    #[inline(always)]
    fn activate_budget(&mut self) {
        if self.state & BUDGET_ACTIVE_MASK == 0 {
            // The value that caused activation is the top-level budgeted value.
            self.state |= BUDGET_ACTIVE_MASK | (1 << BUDGET_VALUES_SHIFT);
        }
    }

    /// Check and increment depth, returning error if limit exceeded.
    #[inline]
    fn enter_nested(&mut self) -> DecodeResult<()> {
        if self.state & DEPTH_MASK >= u32::from(MAXIMUM_DATA_STRUCTURE_DEPTH) {
            return Err(self.invalid_db_error(
                "exceeded maximum data structure depth; database is likely corrupt",
            ));
        }
        self.state += 1;
        Ok(())
    }

    /// Decrement depth when exiting a nested structure.
    #[inline]
    fn exit_nested(&mut self) {
        if self.state & DEPTH_MASK != 0 {
            self.state -= 1;
        }
    }

    /// Reserve logical child values before entering a container. Charging the
    /// complete child count up front bounds both flat containers and pointer
    /// fan-out without touching the scalar decode hot path.
    #[inline(always)]
    fn reserve_values(&mut self, count: usize) -> DecodeResult<()> {
        if self.state & BUDGET_ACTIVE_MASK == 0 {
            return Ok(());
        }
        let values_used = ((self.state & BUDGET_VALUES_MASK) >> BUDGET_VALUES_SHIFT) as usize;
        if count > MAXIMUM_DATA_STRUCTURE_VALUES as usize - values_used {
            return Err(
                self.resource_limit_error("exceeded maximum number of data structure values")
            );
        }
        self.state += (count as u32) << BUDGET_VALUES_SHIFT;
        Ok(())
    }

    #[inline(always)]
    fn reserve_container_values(&mut self, size: usize, type_num: usize) -> DecodeResult<()> {
        // A scalar decoded on its own cannot fan out. The first map or array is
        // the point at which one encoded value can produce unbounded work, so
        // activate the shared operation budget here for every Serde shape.
        self.activate_budget();
        let count = if type_num == TYPE_MAP {
            size.saturating_mul(2)
        } else {
            debug_assert_eq!(type_num, TYPE_ARRAY);
            size
        };
        self.reserve_values(count)
    }

    /// Charge a string or bytes payload against the per-decode byte budget,
    /// returning an error once the total exceeds the limit. This bounds a
    /// payload amplification: many pointers to one large value each recharge the
    /// budget, so the decoder will not repeatedly deliver more payload than the
    /// limit no matter how heavily a target is shared. A custom visitor may
    /// still allocate a representation larger than the borrowed input. Small
    /// fixed-width scalars are not charged.
    #[inline(always)]
    fn count_payload(&mut self, size: usize) -> DecodeResult<()> {
        if self.state & BUDGET_ACTIVE_MASK == 0 {
            return Ok(());
        }
        if size > self.payload_remaining as usize {
            return Err(self.resource_limit_error(
                "exceeded maximum size of data structure string and bytes values",
            ));
        }
        self.payload_remaining -= size as u32;
        Ok(())
    }

    /// Charge identifier payload beyond the portion already covered by the
    /// logical-value budget. Ordinary short schema keys remain free from
    /// payload-counter updates.
    #[inline(always)]
    fn count_identifier_payload(&mut self, size: usize) -> DecodeResult<()> {
        if size <= MAXIMUM_UNCHARGED_IDENTIFIER_BYTES {
            return Ok(());
        }
        self.count_long_identifier_payload(size)
    }

    #[cold]
    #[inline(never)]
    fn count_long_identifier_payload(&mut self, size: usize) -> DecodeResult<()> {
        self.count_payload(size - MAXIMUM_UNCHARGED_IDENTIFIER_BYTES)
    }

    /// Charges a string or bytes value at the current position without
    /// consuming it. Dynamically shaped maps use this for keys because a raw
    /// identifier visitor may copy them without requesting a string decode.
    /// Retains complete string bytes for identifier visitors to reuse.
    #[inline]
    fn count_payload_at_current(&mut self) -> DecodeResult<(bool, Option<CachedKey<'de>>)> {
        let saved_ptr = self.current_ptr;
        let result = self.count_payload_at_current_inner();
        self.current_ptr = saved_ptr;
        result
    }

    // Inline the parsing body so callers that do not use raw identifiers can
    // eliminate the cached bytes and continuation. Keep cursor restoration in
    // the outer method so it also runs when parsing fails.
    #[inline(always)]
    fn count_payload_at_current_inner(&mut self) -> DecodeResult<(bool, Option<CachedKey<'de>>)> {
        let (mut size, mut type_num) = self.size_and_type()?;
        let mut continuation = None;
        if type_num == TYPE_POINTER {
            let target = self.decode_pointer(size);
            continuation = Some(self.current_ptr);
            self.current_ptr = target;
            (size, type_num) = self.size_and_type()?;
            if type_num == TYPE_POINTER {
                return Err(self.invalid_db_error("pointer points to another pointer"));
            }
        }
        if type_num == TYPE_STRING || type_num == TYPE_BYTES {
            self.count_payload(size)?;
            // Cache only complete string payloads. Leave malformed lengths
            // to the requested Serde entry point so its errors and cursor
            // restoration remain unchanged.
            let cached = if type_num == TYPE_STRING {
                self.current_ptr
                    .checked_add(size)
                    .filter(|&end| end <= self.limit)
                    .map(|end| CachedKey {
                        bytes: self.slice(self.current_ptr, end),
                        continuation: continuation.unwrap_or(end),
                    })
            } else {
                None
            };
            return Ok((true, cached));
        }
        Ok((false, None))
    }

    // The error constructors below are cold and never inlined. This keeps
    // successful decode paths small.

    /// Create an InvalidDatabase error with current offset context.
    #[cold]
    #[inline(never)]
    fn invalid_db_error(&self, msg: &str) -> DecoderError {
        MaxMindDbError::invalid_database_at(msg, self.current_ptr).into()
    }

    /// Create a Decoding error with current offset context.
    #[cold]
    #[inline(never)]
    fn decode_error(&self, msg: &str) -> DecoderError {
        MaxMindDbError::decoding_at(msg, self.current_ptr).into()
    }

    /// Create a ResourceLimit error with current offset context.
    #[cold]
    #[inline(never)]
    fn resource_limit_error(&self, msg: &str) -> DecoderError {
        MaxMindDbError::resource_limit_at(msg, self.current_ptr).into()
    }

    #[cold]
    #[inline(never)]
    fn type_mismatch(&self, label: &str, type_num: usize) -> DecoderError {
        if type_num > usize::from(u8::MAX) {
            self.invalid_db_error(&format!("unknown data type: {type_num}"))
        } else {
            self.decode_error(&format!("expected {label}, got type {type_num}"))
        }
    }

    #[inline]
    pub(crate) fn offset(&self) -> usize {
        self.current_ptr
    }

    #[inline(always)]
    fn checked_offset(&self, size: usize, label: &str) -> DecodeResult<usize> {
        let new_offset = self.current_ptr.wrapping_add(size);
        if new_offset < self.current_ptr || new_offset > self.limit {
            return Err(self.invalid_db_error(&format!("{label} of size {size}")));
        }
        Ok(new_offset)
    }

    #[inline(always)]
    fn slice(&self, start: usize, end: usize) -> &'de [u8] {
        debug_assert!(start <= end);
        debug_assert!(end <= self.limit);
        debug_assert!(self.limit <= self.buf.len());
        // SAFETY: `Decoder::new` sets `limit` to `buf.len()`, and the
        // test-only `new_with_limit` asserts `limit <= buf.len()`. All callers
        // reach this helper only after checking `end <= limit`.
        unsafe { self.buf.get_unchecked(start..end) }
    }

    #[inline(always)]
    fn skip_bytes(&mut self, size: usize, label: &str) -> DecodeResult<()> {
        debug_assert!(self.current_ptr <= self.limit);
        if size > self.limit - self.current_ptr {
            return Err(self.invalid_db_error(&format!("{label} of size {size}")));
        }
        self.current_ptr += size;
        Ok(())
    }

    #[inline(always)]
    fn eat_byte(&mut self) -> DecodeResult<u8> {
        if self.current_ptr >= self.limit {
            return Err(self.invalid_db_error("unexpected end of buffer"));
        }
        debug_assert!(self.limit <= self.buf.len());
        // SAFETY: The check above proves `current_ptr < limit`. `Decoder::new`
        // sets `limit` to `buf.len()`, and the test-only `new_with_limit`
        // asserts `limit <= buf.len()`.
        let b = unsafe { *self.buf.get_unchecked(self.current_ptr) };
        self.current_ptr += 1;
        Ok(b)
    }

    #[inline(always)]
    fn size_from_ctrl_byte(&mut self, ctrl_byte: u8, type_num: usize) -> DecodeResult<usize> {
        let size = (ctrl_byte & 0x1f) as usize;
        if size < 29 {
            return Ok(size);
        }
        self.extended_size(size, type_num)
    }

    // Kept separate from size_from_ctrl_byte for speed. The same code written
    // inline there made the lookup and decode benchmarks 2-10% slower.
    #[inline(always)]
    fn extended_size(&mut self, size: usize, type_num: usize) -> DecodeResult<usize> {
        debug_assert!((29..=31).contains(&size));
        // Pointers use the five bits as SSVVV, not as an extended length:
        // sizes 29-31 are four-byte pointers whose low three bits are ignored.
        if type_num == TYPE_POINTER {
            return Ok(size);
        }
        match size {
            29 => Ok(29_usize + self.eat_byte()? as usize),
            30 => {
                let b0 = self.eat_byte()? as usize;
                let b1 = self.eat_byte()? as usize;
                Ok(285_usize + (b0 << 8) + b1)
            }
            _ => {
                let b0 = self.eat_byte()? as usize;
                let b1 = self.eat_byte()? as usize;
                let b2 = self.eat_byte()? as usize;
                Ok(65_821_usize + (b0 << 16) + (b1 << 8) + b2)
            }
        }
    }

    // Only a hint in debug builds. See MAXIMUM_DATA_STRUCTURE_DEPTH.
    #[cfg_attr(debug_assertions, inline)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn size_and_type(&mut self) -> DecodeResult<(usize, usize)> {
        let ctrl_byte = self.eat_byte()?;
        let mut type_num = usize::from(ctrl_byte >> 5);
        // Extended type: type 0 means read next byte for actual type
        if type_num == TYPE_EXTENDED {
            // Widen before adding so malformed bytes cannot overflow.
            type_num = usize::from(self.eat_byte()?) + TYPE_MAP;
        }
        self.size_from_ctrl_byte(ctrl_byte, type_num)
            .map(|size| (size, type_num))
    }

    fn decode_any<V: Visitor<'de>>(&mut self, visitor: V) -> DecodeResult<V::Value> {
        self.activate_budget();
        self.decode_any_impl::<false, V>(visitor)
    }

    fn decode_any_impl<const RAW_STRINGS: bool, V: Visitor<'de>>(
        &mut self,
        visitor: V,
    ) -> DecodeResult<V::Value> {
        match self.decode_any_value::<RAW_STRINGS>()? {
            Value::Any { prev_ptr } => {
                // Pointer dereference - track depth
                self.enter_nested()?;
                let res = self.decode_any_impl::<RAW_STRINGS, V>(visitor);
                self.exit_nested();
                self.current_ptr = prev_ptr;
                res
            }
            Value::Bool(x) => visitor.visit_bool(x),
            Value::Bytes(x) => visitor.visit_borrowed_bytes(x),
            Value::String(x) => visitor.visit_borrowed_str(x),
            Value::RawString(x) => {
                visitor.visit_newtype_struct(BorrowedBytesDeserializer::<DecoderError>::new(x))
            }
            Value::I32(x) => visitor.visit_i32(x),
            Value::U16(x) => visitor.visit_u16(x),
            Value::U32(x) => visitor.visit_u32(x),
            Value::U64(x) => visitor.visit_u64(x),
            Value::U128(x) => visitor.visit_u128(x),
            Value::F64(x) => visitor.visit_f64(x),
            Value::F32(x) => visitor.visit_f32(x),
            // Maps and arrays enter_nested in decode_any_value; exit when done
            Value::Map(x) => {
                let res = visitor.visit_map(x);
                self.exit_nested();
                res
            }
            Value::Array(x) => {
                let res = visitor.visit_seq(x);
                self.exit_nested();
                res
            }
        }
    }

    fn deserialize_fixed_size_array<V>(&mut self, len: usize, visitor: V) -> DecodeResult<V::Value>
    where
        V: Visitor<'de>,
    {
        let (size, type_num) = self.size_and_type()?;
        self.decode_direct(size, type_num, TYPE_ARRAY, "array", |de, size| {
            if size != len {
                return Err(de.decode_error(&format!(
                    "expected tuple of length {len}, got array of length {size}"
                )));
            }

            de.reserve_container_values(size, TYPE_ARRAY)?;
            de.enter_nested()?;
            let res = visitor.visit_seq(ArrayAccess { de, count: size });
            de.exit_nested();
            res
        })
    }

    // Only a hint in debug builds. See MAXIMUM_DATA_STRUCTURE_DEPTH.
    #[cfg_attr(debug_assertions, inline)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn decode_any_value<const RAW_STRINGS: bool>(&mut self) -> DecodeResult<Value<'_, 'de>> {
        let (size, type_num) = self.size_and_type()?;

        Ok(match type_num {
            TYPE_POINTER => {
                let new_ptr = self.decode_pointer(size);
                let prev_ptr = self.current_ptr;
                self.current_ptr = new_ptr;

                Value::Any { prev_ptr }
            }
            TYPE_STRING if RAW_STRINGS => {
                self.count_payload(size)?;
                Value::RawString(self.read_string_bytes(size)?)
            }
            TYPE_STRING => {
                self.count_payload(size)?;
                Value::String(self.decode_string(size)?)
            }
            TYPE_DOUBLE => Value::F64(self.decode_double(size)?),
            TYPE_BYTES => {
                self.count_payload(size)?;
                Value::Bytes(self.decode_bytes(size)?)
            }
            TYPE_UINT16 => Value::U16(self.decode_uint16(size)?),
            TYPE_UINT32 => Value::U32(self.decode_uint32(size)?),
            TYPE_MAP => {
                self.reserve_container_values(size, TYPE_MAP)?;
                self.enter_nested()?;
                self.decode_map(size)
            }
            TYPE_INT32 => Value::I32(self.decode_int(size)?),
            TYPE_UINT64 => Value::U64(self.decode_uint64(size)?),
            TYPE_UINT128 => Value::U128(self.decode_uint128(size)?),
            TYPE_ARRAY => {
                self.reserve_container_values(size, TYPE_ARRAY)?;
                self.enter_nested()?;
                self.decode_array(size)
            }
            TYPE_BOOL => Value::Bool(self.decode_bool(size)?),
            TYPE_FLOAT => Value::F32(self.decode_float(size)?),
            u => return Err(self.invalid_db_error(&format!("unknown data type: {u}"))),
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
            s => Err(self.invalid_db_error(&format!("bool of size {s}"))),
        }
    }

    fn decode_bytes(&mut self, size: usize) -> DecodeResult<&'de [u8]> {
        let new_offset = self.checked_offset(size, "bytes")?;
        let u8_slice = self.slice(self.current_ptr, new_offset);
        self.current_ptr = new_offset;

        Ok(u8_slice)
    }

    fn decode_float(&mut self, size: usize) -> DecodeResult<f32> {
        let new_offset = self.checked_offset(size, "float")?;
        let value: [u8; 4] = self
            .slice(self.current_ptr, new_offset)
            .try_into()
            .map_err(|_| self.invalid_db_error(&format!("float of size {size}")))?;
        self.current_ptr = new_offset;
        let float_value = f32::from_be_bytes(value);
        Ok(float_value)
    }

    fn decode_double(&mut self, size: usize) -> DecodeResult<f64> {
        let new_offset = self.checked_offset(size, "double")?;
        let value: [u8; 8] = self
            .slice(self.current_ptr, new_offset)
            .try_into()
            .map_err(|_| self.invalid_db_error(&format!("double of size {size}")))?;
        self.current_ptr = new_offset;
        let float_value = f64::from_be_bytes(value);
        Ok(float_value)
    }

    decode_int_like!(decode_uint64, u64, 8, "u64", 0_u64);
    decode_int_like!(decode_uint128, u128, 16, "u128", 0_u128);

    #[inline(always)]
    fn read_u32_be(&mut self, size: usize, label: &str) -> DecodeResult<u32> {
        if size > 4 {
            return Err(self.invalid_db_error(&format!("{label} of size {size}")));
        }
        let new_offset = self
            .current_ptr
            .checked_add(size)
            .filter(|&offset| offset <= self.limit)
            .ok_or_else(|| self.invalid_db_error(&format!("{label} of size {}", size)))?;
        let p = self.current_ptr;
        let value = match size {
            0 => 0,
            1 => self.buf[p] as u32,
            2 => ((self.buf[p] as u32) << 8) | self.buf[p + 1] as u32,
            3 => {
                ((self.buf[p] as u32) << 16)
                    | ((self.buf[p + 1] as u32) << 8)
                    | self.buf[p + 2] as u32
            }
            _ => {
                ((self.buf[p] as u32) << 24)
                    | ((self.buf[p + 1] as u32) << 16)
                    | ((self.buf[p + 2] as u32) << 8)
                    | self.buf[p + 3] as u32
            }
        };
        self.current_ptr = new_offset;
        Ok(value)
    }

    #[inline(always)]
    fn decode_uint32(&mut self, size: usize) -> DecodeResult<u32> {
        self.read_u32_be(size, "u32")
    }

    #[inline(always)]
    fn decode_uint16(&mut self, size: usize) -> DecodeResult<u16> {
        if size > 2 {
            return Err(self.invalid_db_error(&format!("u16 of size {size}")));
        }
        let new_offset = self
            .current_ptr
            .checked_add(size)
            .filter(|&offset| offset <= self.limit)
            .ok_or_else(|| self.invalid_db_error(&format!("u16 of size {}", size)))?;
        let p = self.current_ptr;
        let value = match size {
            0 => 0,
            1 => self.buf[p] as u16,
            _ => ((self.buf[p] as u16) << 8) | self.buf[p + 1] as u16,
        };
        self.current_ptr = new_offset;
        Ok(value)
    }

    fn decode_int(&mut self, size: usize) -> DecodeResult<i32> {
        self.read_u32_be(size, "i32").map(|value| value as i32)
    }

    fn decode_map(&mut self, size: usize) -> Value<'_, 'de> {
        Value::Map(MapAccessor {
            de: self,
            count: size * 2,
        })
    }

    // Only a hint in debug builds. See MAXIMUM_DATA_STRUCTURE_DEPTH.
    #[cfg_attr(debug_assertions, inline)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn decode_pointer(&mut self, size: usize) -> usize {
        let pointer_size = ((size >> 3) & 0x3) + 1;
        let p = self.current_ptr;
        let limit = self.limit;
        let new_offset = match p.checked_add(pointer_size) {
            Some(offset) if offset <= limit => offset,
            _ => {
                // Clamp to the end of the buffer so the next decode step fails
                // with a normal bounds error instead of panicking here.
                self.current_ptr = limit;
                return limit;
            }
        };
        let pointer_bytes = self.slice(p, new_offset);
        self.current_ptr = new_offset;

        match pointer_size {
            1 => ((size & 0x7) << 8) | usize::from(pointer_bytes[0]),
            2 => {
                (((size & 0x7) << 16)
                    | (usize::from(pointer_bytes[0]) << 8)
                    | usize::from(pointer_bytes[1]))
                    + 2048
            }
            3 => {
                (((size & 0x7) << 24)
                    | (usize::from(pointer_bytes[0]) << 16)
                    | (usize::from(pointer_bytes[1]) << 8)
                    | usize::from(pointer_bytes[2]))
                    + 526_336
            }
            _ => {
                (usize::from(pointer_bytes[0]) << 24)
                    | (usize::from(pointer_bytes[1]) << 16)
                    | (usize::from(pointer_bytes[2]) << 8)
                    | usize::from(pointer_bytes[3])
            }
        }
    }

    #[cfg(feature = "unsafe-str-decode")]
    #[inline(always)]
    fn decode_string(&mut self, size: usize) -> DecodeResult<&'de str> {
        use std::str::from_utf8_unchecked;

        let new_offset = self.checked_offset(size, "string")?;
        let bytes = self.slice(self.current_ptr, new_offset);
        self.current_ptr = new_offset;
        // SAFETY:
        // A corrupt maxminddb will cause undefined behaviour.
        // If the caller has verified the integrity of their database and trusts their upstream
        // provider, they can opt-into the performance gains provided by this unsafe function via
        // the `unsafe-str-decode` feature flag.
        let v = unsafe { from_utf8_unchecked(bytes) };
        Ok(v)
    }

    #[cfg(not(feature = "unsafe-str-decode"))]
    #[inline(always)]
    fn decode_string(&mut self, size: usize) -> DecodeResult<&'de str> {
        use std::str::from_utf8;
        use std::str::from_utf8_unchecked;

        let new_offset = self.checked_offset(size, "string")?;
        let bytes = self.slice(self.current_ptr, new_offset);
        self.current_ptr = new_offset;
        if is_ascii(bytes) {
            // ASCII is valid UTF-8, so this avoids the full validator fast path.
            // SAFETY: `is_ascii()` guarantees UTF-8 validity.
            let v = unsafe { from_utf8_unchecked(bytes) };
            return Ok(v);
        }
        match from_utf8(bytes) {
            Ok(v) => Ok(v),
            Err(_) => Err(self.invalid_db_error("invalid UTF-8 in string")),
        }
    }

    // ========== Navigation methods for path decoding and verification ==========

    /// Peeks at the type and size without consuming it.
    /// Returns (size, type_num) and restores the position.
    pub(crate) fn peek_type(&mut self) -> DecodeResult<(usize, usize)> {
        let saved_ptr = self.current_ptr;
        let result = self.size_and_type_following_pointers()?;
        self.current_ptr = saved_ptr;
        Ok(result)
    }

    /// Consumes a map or array header in one pass, following a pointer if needed.
    pub(crate) fn consume_container_header(&mut self) -> DecodeResult<(usize, usize)> {
        let (size, type_num) = self.size_and_type_following_pointers()?;
        if type_num == TYPE_MAP || type_num == TYPE_ARRAY {
            self.reserve_container_values(size, type_num)?;
        }
        Ok((size, type_num))
    }

    /// Gets size and type, following any pointers.
    fn size_and_type_following_pointers(&mut self) -> DecodeResult<(usize, usize)> {
        let (size, type_num) = self.size_and_type()?;
        if type_num != TYPE_POINTER {
            return Ok((size, type_num));
        }

        self.current_ptr = self.decode_pointer(size);
        let (size, type_num) = self.size_and_type()?;
        if type_num == TYPE_POINTER {
            return Err(self.invalid_db_error("pointer points to another pointer"));
        }

        Ok((size, type_num))
    }

    #[inline(always)]
    fn decode_direct<T, F>(
        &mut self,
        size: usize,
        type_num: usize,
        expected_type: usize,
        label: &str,
        decode: F,
    ) -> DecodeResult<T>
    where
        F: FnOnce(&mut Self, usize) -> DecodeResult<T>,
    {
        self.decode_direct_or(
            size,
            type_num,
            expected_type,
            (),
            |de, size, ()| decode(de, size),
            |de, _, type_num, ()| Err(de.type_mismatch(label, type_num)),
        )
    }

    /// Decodes a value of `expected_type`, following one pointer. Values of
    /// any other type go to `mismatch` with their size and type, positioned at
    /// their payload. A pointer to another pointer is rejected as an invalid
    /// database without calling `mismatch`. `context` is passed to whichever
    /// closure runs, so both can take ownership of the same visitor.
    #[inline(always)]
    fn decode_direct_or<C, T, F, M>(
        &mut self,
        size: usize,
        type_num: usize,
        expected_type: usize,
        context: C,
        decode: F,
        mismatch: M,
    ) -> DecodeResult<T>
    where
        F: FnOnce(&mut Self, usize, C) -> DecodeResult<T>,
        M: FnOnce(&mut Self, usize, usize, C) -> DecodeResult<T>,
    {
        debug_assert_ne!(expected_type, TYPE_POINTER);
        let (size, continuation) = match type_num {
            TYPE_POINTER => {
                let new_ptr = self.decode_pointer(size);
                let saved_ptr = self.current_ptr;
                self.current_ptr = new_ptr;
                if let Err(error) = self.enter_nested() {
                    self.current_ptr = saved_ptr;
                    return Err(error);
                }
                let (size, type_num) = match self.size_and_type() {
                    Ok(header) => header,
                    Err(error) => {
                        self.exit_nested();
                        self.current_ptr = saved_ptr;
                        return Err(error);
                    }
                };
                if type_num == expected_type {
                    (size, Some(saved_ptr))
                } else {
                    // `expected_type` is never a pointer, so this branch also
                    // covers pointers to pointers.
                    let result = if type_num == TYPE_POINTER {
                        Err(self.invalid_db_error("pointer points to another pointer"))
                    } else {
                        mismatch(self, size, type_num, context)
                    };
                    self.exit_nested();
                    self.current_ptr = saved_ptr;
                    return result;
                }
            }
            t if t == expected_type => (size, None),
            _ => return mismatch(self, size, type_num, context),
        };
        // One payload call lets visitor code inline without duplicating it
        // for pointers and inline values.
        let result = decode(self, size, context);
        if let Some(saved_ptr) = continuation {
            self.exit_nested();
            self.current_ptr = saved_ptr;
        }
        result
    }

    /// Decodes a value of MMDB type `type_num` for a field of integer type
    /// `T`, positioned at its payload. Any MMDB integer type is accepted, and
    /// [`visit_integer`] decides by value. Other types are a type mismatch.
    fn decode_integer<T, V>(
        &mut self,
        size: usize,
        type_num: usize,
        label: &str,
        visitor: V,
    ) -> DecodeResult<V::Value>
    where
        T: IntegerTarget,
        V: Visitor<'de>,
    {
        let offset = self.current_ptr;
        let result: DecodeResult<V::Value> = match type_num {
            TYPE_UINT16 => {
                visit_integer::<T, _, _, _>(self.decode_uint16(size)?, visitor, |visitor, v| {
                    visitor.visit_u16(v)
                })
            }
            TYPE_UINT32 => {
                visit_integer::<T, _, _, _>(self.decode_uint32(size)?, visitor, |visitor, v| {
                    visitor.visit_u32(v)
                })
            }
            TYPE_UINT64 => {
                visit_integer::<T, _, _, _>(self.decode_uint64(size)?, visitor, |visitor, v| {
                    visitor.visit_u64(v)
                })
            }
            TYPE_UINT128 => {
                // `U128Visitor` sends a value that fits in a `u64` to
                // `visit_u64`, which Serde's narrower visitors implement.
                visit_integer::<T, _, _, _>(self.decode_uint128(size)?, visitor, |visitor, v| {
                    U128Visitor(visitor).visit_u128(v)
                })
            }
            TYPE_INT32 => {
                visit_integer::<T, _, _, _>(self.decode_int(size)?, visitor, |visitor, v| {
                    visitor.visit_i32(v)
                })
            }
            _ => return Err(self.type_mismatch(label, type_num)),
        };
        // An out-of-range value fails in the visitor, which has no offset.
        // Add the one a type mismatch here would have reported.
        result.map_err(|err| with_decoding_offset(err, offset))
    }

    #[inline(always)]
    fn read_string_bytes(&mut self, size: usize) -> DecodeResult<&'de [u8]> {
        let new_offset = self
            .current_ptr
            .checked_add(size)
            .ok_or_else(|| self.invalid_db_error("string length exceeds buffer"))?;
        if new_offset > self.limit {
            return Err(self.invalid_db_error("string length exceeds buffer"));
        }
        let bytes = self.slice(self.current_ptr, new_offset);
        self.current_ptr = new_offset;
        Ok(bytes)
    }

    /// Reads a string's bytes directly, following pointers if needed.
    /// Does NOT validate UTF-8.
    #[inline]
    pub(crate) fn read_str_as_bytes(&mut self) -> DecodeResult<&'de [u8]> {
        // Keys are strings, optionally behind one pointer. Handle those
        // headers directly, including extended lengths, without retrying a
        // general decode for valid inline strings or wider pointers.
        let offset = self.current_ptr;
        let ctrl = self.eat_byte()?;
        match usize::from(ctrl >> 5) {
            TYPE_STRING => {
                let size = self.size_from_ctrl_byte(ctrl, TYPE_STRING)?;
                self.count_payload(size)?;
                return self.read_string_bytes(size);
            }
            TYPE_POINTER => {
                let target = self.decode_pointer(usize::from(ctrl & 0x1f));
                let continuation = self.current_ptr;
                self.current_ptr = target;
                let ctrl = self.eat_byte()?;
                if usize::from(ctrl >> 5) == TYPE_STRING {
                    let size = self.size_from_ctrl_byte(ctrl, TYPE_STRING)?;
                    let result = self
                        .count_payload(size)
                        .and_then(|()| self.read_string_bytes(size));
                    self.current_ptr = continuation;
                    return result;
                }
            }
            _ => {}
        }
        self.current_ptr = offset;
        self.read_str_as_bytes_slow()
    }

    // Preserve the general parser's error details and cursor behavior for
    // unexpected types. Tests also use this as a reference for valid keys.
    #[cold]
    fn read_str_as_bytes_slow(&mut self) -> DecodeResult<&'de [u8]> {
        let (size, type_num) = self.size_and_type()?;
        match type_num {
            TYPE_POINTER => {
                let new_ptr = self.decode_pointer(size);
                let saved_ptr = self.current_ptr;
                self.current_ptr = new_ptr;
                let (size, type_num) = self.size_and_type()?;
                let result = if type_num == TYPE_POINTER {
                    Err(self.invalid_db_error("pointer points to another pointer"))
                } else if type_num == TYPE_STRING {
                    self.count_payload(size)
                        .and_then(|()| self.read_string_bytes(size))
                } else {
                    Err(self.invalid_db_error(&format!("expected string, got type {type_num}")))
                };
                self.current_ptr = saved_ptr;
                result
            }
            TYPE_STRING => {
                self.count_payload(size)?;
                self.read_string_bytes(size)
            }
            _ => Err(self.invalid_db_error(&format!("expected string, got type {type_num}"))),
        }
    }

    /// Fast-path identifier decoding:
    /// - Returns `Ok(Some(bytes))` and consumes the identifier when it is a string.
    /// - Returns `Ok(None)` and restores `current_ptr` when the next value is not a string.
    /// - Returns `Err` for malformed pointer chains or invalid string lengths.
    #[inline(always)]
    fn try_read_identifier_bytes(&mut self) -> DecodeResult<Option<&'de [u8]>> {
        let saved_ptr = self.current_ptr;
        let (size, type_num) = self.size_and_type()?;
        match type_num {
            TYPE_STRING => {
                self.count_identifier_payload(size)?;
                self.read_string_bytes(size).map(Some)
            }
            TYPE_POINTER => {
                let new_ptr = self.decode_pointer(size);
                let after_pointer = self.current_ptr;
                self.current_ptr = new_ptr;
                let (inner_size, inner_type) = self.size_and_type()?;
                let result = if inner_type == TYPE_POINTER {
                    Err(self.invalid_db_error("pointer points to another pointer"))
                } else if inner_type == TYPE_STRING {
                    let payload_result = self.count_identifier_payload(inner_size);
                    match payload_result {
                        Ok(()) => self.read_string_bytes(inner_size).map(Some),
                        Err(error) => Err(error),
                    }
                } else {
                    Ok(None)
                };
                // decode_pointer(size) temporarily dereferences by moving current_ptr
                // to new_ptr; after size_and_type/read_string_bytes on the pointed
                // value, restoring current_ptr = after_pointer resumes parsing right
                // after the original pointer bytes. When result is Ok(None), also
                // reset current_ptr = saved_ptr so the non-string identifier can be
                // parsed normally by the caller without consuming the pointer token.
                self.current_ptr = after_pointer;
                if matches!(result, Ok(None)) {
                    self.current_ptr = saved_ptr;
                }
                result
            }
            _ => {
                self.current_ptr = saved_ptr;
                Ok(None)
            }
        }
    }

    /// Skips the current encoded value without expanding pointer targets.
    pub(crate) fn skip_value(&mut self) -> DecodeResult<()> {
        let (size, type_num) = self.size_and_type()?;
        self.skip_value_inner(size, type_num, 0)
    }

    /// Skips the current value and validates any referenced pointer targets.
    pub(crate) fn skip_value_for_verification(
        &mut self,
        state: &mut VerificationState,
    ) -> DecodeResult<()> {
        let offset = self.current_ptr;
        if state.validated.contains(&offset) {
            return Ok(());
        }
        if !state.active.insert(offset) {
            return Err(
                self.invalid_db_error(&format!("cyclic data pointer references offset {offset}"))
            );
        }

        let result = (|| {
            let (size, type_num) = self.size_and_type()?;
            self.skip_value_inner_for_verification(size, type_num, 0, state)?;
            self.validate_skip_end()
        })();

        state.active.remove(&offset);
        if result.is_ok() {
            state.validated.insert(offset);
        }
        result
    }

    #[inline(always)]
    pub(crate) fn validate_skip_end(&mut self) -> DecodeResult<()> {
        if self.current_ptr > self.limit {
            return Err(self.invalid_db_error("skipped value extends beyond buffer"));
        }
        Ok(())
    }

    #[inline(always)]
    fn check_skip_depth(&self, skip_depth: u16) -> DecodeResult<u16> {
        if skip_depth == MAXIMUM_SKIPPED_DATA_STRUCTURE_DEPTH {
            return self.skip_depth_error();
        }
        Ok(skip_depth + 1)
    }

    #[cold]
    fn skip_depth_error(&self) -> DecodeResult<u16> {
        Err(self
            .invalid_db_error("exceeded maximum data structure depth; database is likely corrupt"))
    }

    #[inline(always)]
    fn skip_value_inner(
        &mut self,
        size: usize,
        type_num: usize,
        skip_depth: u16,
    ) -> DecodeResult<()> {
        // Headers and scalar payloads validate every cursor advance. A
        // successful recursive skip therefore already guarantees that the
        // cursor remains within the decoder limit.
        match type_num {
            TYPE_POINTER => {
                // The pointer token is the complete skipped value. Its target
                // is not materialized, so following it would only amplify work
                // the destination did not request. Full database verification
                // still validates referenced targets.
                let pointer_size = ((size >> 3) & 0x3) + 1;
                self.checked_offset(pointer_size, "pointer")?;
                self.decode_pointer(size);
                Ok(())
            }
            TYPE_STRING | TYPE_BYTES => {
                // String or Bytes - skip size bytes
                let label = if type_num == TYPE_STRING {
                    "string"
                } else {
                    "bytes"
                };
                self.skip_bytes(size, label)
            }
            TYPE_DOUBLE => {
                // Double - must be exactly 8 bytes
                if size != 8 {
                    return Err(self.invalid_db_error(&format!("double of size {size}")));
                }
                self.skip_bytes(size, "double")
            }
            TYPE_FLOAT => {
                // Float - must be exactly 4 bytes
                if size != 4 {
                    return Err(self.invalid_db_error(&format!("float of size {size}")));
                }
                self.skip_bytes(size, "float")
            }
            TYPE_UINT16 | TYPE_UINT32 | TYPE_INT32 | TYPE_UINT64 | TYPE_UINT128 => {
                // Numeric types - skip size bytes
                let label = match type_num {
                    TYPE_UINT16 => "u16",
                    TYPE_UINT32 => "u32",
                    TYPE_INT32 => "i32",
                    TYPE_UINT64 => "u64",
                    TYPE_UINT128 => "u128",
                    _ => unreachable!(),
                };
                let max_size = match type_num {
                    TYPE_UINT16 => 2,
                    TYPE_UINT32 | TYPE_INT32 => 4,
                    TYPE_UINT64 => 8,
                    TYPE_UINT128 => 16,
                    _ => unreachable!(),
                };
                if size > max_size {
                    return Err(self.invalid_db_error(&format!("{label} of size {size}")));
                }
                self.skip_bytes(size, label)
            }
            TYPE_BOOL => {
                // Boolean - size field IS the value, no data bytes to skip
                self.decode_bool(size).map(|_| ())
            }
            TYPE_MAP => {
                // Map - skip size key-value pairs
                self.reserve_container_values(size, TYPE_MAP)?;
                let child_depth = self.check_skip_depth(skip_depth)?;
                for _ in 0..size {
                    // key
                    self.skip_value_with_depth(child_depth)?;
                    // value
                    self.skip_value_with_depth(child_depth)?;
                }
                Ok(())
            }
            TYPE_ARRAY => {
                // Array - skip size elements
                self.reserve_container_values(size, TYPE_ARRAY)?;
                let child_depth = self.check_skip_depth(skip_depth)?;
                for _ in 0..size {
                    self.skip_value_with_depth(child_depth)?;
                }
                Ok(())
            }
            u => Err(self.invalid_db_error(&format!("unknown data type: {u}"))),
        }
    }

    #[inline(always)]
    fn skip_value_with_depth(&mut self, skip_depth: u16) -> DecodeResult<()> {
        let (size, type_num) = self.size_and_type()?;
        self.skip_value_inner(size, type_num, skip_depth)
    }

    fn skip_value_inner_for_verification(
        &mut self,
        size: usize,
        type_num: usize,
        skip_depth: u16,
        state: &mut VerificationState,
    ) -> DecodeResult<()> {
        // Charge every visited value, including inline children and pointers
        // to cached targets, before traversal. Headers take constant work.
        state.charge(1, self.current_ptr)?;
        match type_num {
            TYPE_STRING => {
                let end = self.checked_offset(size, "string")?;
                state.charge(size, self.current_ptr)?;
                let bytes = self.slice(self.current_ptr, end);
                self.current_ptr = end;
                std::str::from_utf8(bytes)
                    .map(|_| ())
                    .map_err(|_| self.invalid_db_error("invalid UTF-8 in string"))
            }
            TYPE_POINTER => {
                let target = self.decode_pointer(size);
                let child_depth = self.check_skip_depth(skip_depth)?;
                self.verify_pointer_target(target, child_depth, state)
            }
            TYPE_MAP => {
                let child_depth = self.check_skip_depth(skip_depth)?;
                for _ in 0..size {
                    self.skip_value_with_verification(child_depth, state)?;
                    self.skip_value_with_verification(child_depth, state)?;
                }
                self.validate_skip_end()
            }
            TYPE_ARRAY => {
                let child_depth = self.check_skip_depth(skip_depth)?;
                for _ in 0..size {
                    self.skip_value_with_verification(child_depth, state)?;
                }
                self.validate_skip_end()
            }
            _ => self.skip_value_inner(size, type_num, skip_depth),
        }
    }

    fn skip_value_with_verification(
        &mut self,
        skip_depth: u16,
        state: &mut VerificationState,
    ) -> DecodeResult<()> {
        let (size, type_num) = self.size_and_type()?;
        self.skip_value_inner_for_verification(size, type_num, skip_depth, state)
    }

    fn verify_pointer_target(
        &mut self,
        target: usize,
        skip_depth: u16,
        state: &mut VerificationState,
    ) -> DecodeResult<()> {
        if state.validated.contains(&target) {
            return Ok(());
        }
        if !state.active.insert(target) {
            return Err(
                self.invalid_db_error(&format!("cyclic data pointer references offset {target}"))
            );
        }

        let continuation = self.current_ptr;
        self.current_ptr = target;
        let result = (|| {
            let (size, type_num) = self.size_and_type()?;
            self.skip_value_inner_for_verification(size, type_num, skip_depth, state)?;
            self.validate_skip_end()
        })();
        self.current_ptr = continuation;

        state.active.remove(&target);
        if result.is_ok() {
            state.validated.insert(target);
        }
        result
    }
}

// Keep successful scalar and visitor results small by boxing the error.
// Public reader methods return the original error after decoding finishes.
pub(crate) type DecoderError = Box<MaxMindDbError>;

pub type DecodeResult<T> = Result<T, DecoderError>;

/// Deserializes any MaxMind DB value while exposing strings as raw bytes.
///
/// This helper is intended for format adapters that validate strings while
/// converting them to another runtime's native string type. MMDB string values
/// are delivered to [`Visitor::visit_newtype_struct`], which the adapter's
/// visitor must implement. Its nested deserializer answers every
/// `deserialize_*` call with [`Visitor::visit_borrowed_bytes`]; calling
/// [`Deserializer::deserialize_bytes`] is the conventional choice. Genuine
/// MMDB byte values continue to be delivered directly to
/// [`Visitor::visit_borrowed_bytes`], so callers can distinguish the two
/// types. Values decoded through this helper share the operation's expansion
/// budget.
///
/// Callers decoding nested maps or arrays should invoke this helper again from
/// the [`DeserializeSeed`] used for each nested value. Map keys can be read as
/// unvalidated bytes with [`Deserializer::deserialize_identifier`]. Raw-string
/// mode applies only to the value for which this helper is invoked. Nested
/// values decoded without re-invoking it silently use normal string decoding,
/// including the `unsafe-str-decode` behavior when that feature is enabled.
/// Pointers are followed transparently and preserve the selected mode.
///
/// This function has its special effect only with this crate's deserializer;
/// other Serde deserializers may treat the request as an ordinary newtype
/// struct. The adapter is responsible for ensuring strict UTF-8 validation if
/// malformed database strings must remain errors, as some runtimes replace
/// invalid sequences instead. Unlike the `unsafe-str-decode` feature, this
/// function itself never constructs an unvalidated Rust `str`.
pub fn deserialize_any_with_raw_strings<'de, D, V>(
    deserializer: D,
    visitor: V,
) -> Result<V::Value, D::Error>
where
    D: Deserializer<'de>,
    V: Visitor<'de>,
{
    deserializer.deserialize_newtype_struct(RAW_STRINGS_NEWTYPE, visitor)
}

impl<'de: 'a, 'a> de::Deserializer<'de> for &'a mut Decoder<'de> {
    type Error = DecoderError;

    fn deserialize_any<V>(self, visitor: V) -> DecodeResult<V::Value>
    where
        V: Visitor<'de>,
    {
        self.decode_any(visitor)
    }

    fn deserialize_option<V>(self, visitor: V) -> DecodeResult<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_some(self)
    }

    deserialize_direct_scalar!(deserialize_bool, TYPE_BOOL, "bool", visit_bool, decode_bool);

    deserialize_integer!(
        deserialize_u16,
        TYPE_UINT16,
        "u16",
        visit_u16,
        decode_uint16,
        u16
    );

    deserialize_integer!(
        deserialize_u32,
        TYPE_UINT32,
        "u32",
        visit_u32,
        decode_uint32,
        u32
    );

    deserialize_integer!(
        deserialize_u64,
        TYPE_UINT64,
        "u64",
        visit_u64,
        decode_uint64,
        u64
    );

    deserialize_integer!(
        deserialize_u128,
        TYPE_UINT128,
        "u128",
        visit_u128,
        decode_uint128,
        u128
    );

    deserialize_integer!(
        deserialize_i32,
        TYPE_INT32,
        "i32",
        visit_i32,
        decode_int,
        i32
    );

    deserialize_integer_any!(
        deserialize_u8,
        deserialize_i8,
        deserialize_i16,
        deserialize_i64
    );

    deserialize_direct_scalar!(
        deserialize_f32,
        TYPE_FLOAT,
        "float",
        visit_f32,
        decode_float
    );

    deserialize_widening_scalar!(
        deserialize_f64,
        TYPE_DOUBLE,
        "double",
        visit_f64,
        decode_double,
        f64,
        TYPE_FLOAT => decode_float
    );

    deserialize_direct_payload!(
        deserialize_str,
        TYPE_STRING,
        "string",
        visit_borrowed_str,
        decode_string
    );

    fn deserialize_string<V>(self, visitor: V) -> DecodeResult<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_str(visitor)
    }

    deserialize_direct_payload!(
        deserialize_bytes,
        TYPE_BYTES,
        "bytes",
        visit_borrowed_bytes,
        decode_bytes
    );

    fn deserialize_byte_buf<V>(self, visitor: V) -> DecodeResult<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_bytes(visitor)
    }

    fn deserialize_seq<V>(self, visitor: V) -> DecodeResult<V::Value>
    where
        V: Visitor<'de>,
    {
        let (size, type_num) = self.size_and_type()?;
        self.decode_direct(size, type_num, TYPE_ARRAY, "array", |de, size| {
            de.reserve_container_values(size, TYPE_ARRAY)?;
            de.enter_nested()?;
            let res = visitor.visit_seq(ArrayAccess { de, count: size });
            de.exit_nested();
            res
        })
    }

    fn deserialize_tuple<V>(self, len: usize, visitor: V) -> DecodeResult<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_fixed_size_array(len, visitor)
    }

    fn deserialize_tuple_struct<V>(
        self,
        _name: &'static str,
        len: usize,
        visitor: V,
    ) -> DecodeResult<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_fixed_size_array(len, visitor)
    }

    fn deserialize_map<V>(self, visitor: V) -> DecodeResult<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_map_impl(visitor)
    }

    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> DecodeResult<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_map_impl(visitor)
    }

    fn is_human_readable(&self) -> bool {
        false
    }

    fn deserialize_ignored_any<V>(self, visitor: V) -> DecodeResult<V::Value>
    where
        V: Visitor<'de>,
    {
        self.skip_value()?;
        visitor.visit_unit()
    }

    fn deserialize_enum<V>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> DecodeResult<V::Value>
    where
        V: Visitor<'de>,
    {
        self.activate_budget();
        visitor.visit_enum(EnumAccessor { de: self })
    }

    fn deserialize_identifier<V>(self, visitor: V) -> DecodeResult<V::Value>
    where
        V: Visitor<'de>,
    {
        match self.try_read_identifier_bytes()? {
            Some(bytes) => visitor.visit_borrowed_bytes(bytes),
            None => self.decode_any(visitor),
        }
    }

    fn deserialize_newtype_struct<V>(self, name: &'static str, visitor: V) -> DecodeResult<V::Value>
    where
        V: Visitor<'de>,
    {
        if name == RAW_STRINGS_NEWTYPE {
            self.activate_budget();
            self.decode_any_impl::<true, V>(visitor)
        } else {
            self.activate_budget();
            visitor.visit_newtype_struct(self)
        }
    }

    // `i128` accepts every MMDB integer that fits through Serde's own visitor.
    forward_to_deserialize_any! {
        i128 char unit unit_struct
    }
}

impl<'de> Decoder<'de> {
    fn deserialize_map_impl<V>(&mut self, visitor: V) -> DecodeResult<V::Value>
    where
        V: Visitor<'de>,
    {
        let (size, type_num) = self.size_and_type()?;
        self.decode_direct(size, type_num, TYPE_MAP, "map", |de, size| {
            de.reserve_container_values(size, TYPE_MAP)?;
            de.enter_nested()?;
            let res = visitor.visit_map(MapAccessor::<false> {
                de,
                count: size * 2,
            });
            de.exit_nested();
            res
        })
    }
}

struct ArrayAccess<'a, 'de: 'a> {
    de: &'a mut Decoder<'de>,
    count: usize,
}

// `SeqAccess` is provided to the `Visitor` to give it the ability to iterate
// through elements of the sequence.
impl<'de> SeqAccess<'de> for ArrayAccess<'_, 'de> {
    type Error = DecoderError;

    #[inline(always)]
    fn size_hint(&self) -> Option<usize> {
        // Never let a corrupt declared count drive an allocation larger than
        // the remaining encoded data can possibly fill.
        // Cursor advances are checked, so ordinary subtraction is sufficient.
        debug_assert!(self.de.current_ptr <= self.de.limit);
        Some(self.count.min(self.de.limit - self.de.current_ptr))
    }

    fn next_element_seed<T>(&mut self, seed: T) -> DecodeResult<Option<T::Value>>
    where
        T: DeserializeSeed<'de>,
    {
        // Check if there are no more elements.
        if self.count == 0 {
            if self.de.current_ptr > self.de.limit {
                return Err(self
                    .de
                    .invalid_db_error("skipped value extends beyond buffer"));
            }
            return Ok(None);
        }
        self.count -= 1;

        // Deserialize an array element.
        seed.deserialize(&mut *self.de).map(Some)
    }
}

struct MapAccessor<'a, 'de: 'a, const BUDGETED: bool = false> {
    de: &'a mut Decoder<'de>,
    count: usize,
}

// `MapAccess` is provided to the `Visitor` to give it the ability to iterate
// through entries of the map.
impl<'de, const BUDGETED: bool> MapAccess<'de> for MapAccessor<'_, 'de, BUDGETED> {
    type Error = DecoderError;

    #[inline(always)]
    fn size_hint(&self) -> Option<usize> {
        // Each map entry needs at least one control byte for both key and value.
        // Cursor advances are checked, so ordinary subtraction is sufficient.
        debug_assert!(self.de.current_ptr <= self.de.limit);
        Some((self.count / 2).min((self.de.limit - self.de.current_ptr) / 2))
    }

    fn next_key_seed<K>(&mut self, seed: K) -> DecodeResult<Option<K::Value>>
    where
        K: DeserializeSeed<'de>,
    {
        // Check if there are no more entries.
        if self.count == 0 {
            if self.de.current_ptr > self.de.limit {
                return Err(self
                    .de
                    .invalid_db_error("skipped value extends beyond buffer"));
            }
            return Ok(None);
        }
        self.count -= 1;

        if BUDGETED {
            let payload_remaining_before = self.de.payload_remaining;
            let (payload_precharged, cached) = self.de.count_payload_at_current()?;
            let payload_remaining_after = self.de.payload_remaining;

            // Let the seed perform its ordinary payload charge, while retaining
            // the precharge if an identifier visitor does not request one. This
            // avoids disabling a budget that deserialize_any can reactivate and
            // keeps the ordinary payload counter free of a map-key-only branch.
            self.de.payload_remaining = payload_remaining_before;
            let result = seed
                .deserialize(KeyDeserializer {
                    decoder: self.de,
                    cached,
                })
                .map(Some);
            if payload_precharged {
                self.de.payload_remaining = self.de.payload_remaining.min(payload_remaining_after);
            }
            return result;
        }

        // Deserialize a map key.
        seed.deserialize(&mut *self.de).map(Some)
    }

    fn next_value_seed<V>(&mut self, seed: V) -> DecodeResult<V::Value>
    where
        V: DeserializeSeed<'de>,
    {
        // Check if there are no more entries.
        if self.count == 0 {
            return Err(self.de.decode_error("no more entries"));
        }
        self.count -= 1;

        // Deserialize a map value.
        seed.deserialize(&mut *self.de)
    }
}

struct EnumAccessor<'a, 'de: 'a> {
    de: &'a mut Decoder<'de>,
}

impl<'de> de::EnumAccess<'de> for EnumAccessor<'_, 'de> {
    type Error = DecoderError;
    type Variant = Self;

    fn variant_seed<V>(self, seed: V) -> DecodeResult<(V::Value, Self::Variant)>
    where
        V: DeserializeSeed<'de>,
    {
        // Deserialize the variant identifier (string)
        let variant = seed.deserialize(&mut *self.de)?;
        Ok((variant, self))
    }
}

impl<'de> de::VariantAccess<'de> for EnumAccessor<'_, 'de> {
    type Error = DecoderError;

    fn unit_variant(self) -> DecodeResult<()> {
        Ok(())
    }

    fn newtype_variant_seed<T>(self, seed: T) -> DecodeResult<T::Value>
    where
        T: DeserializeSeed<'de>,
    {
        self.de.reserve_values(1)?;
        self.de.enter_nested()?;
        let result = seed.deserialize(&mut *self.de);
        self.de.exit_nested();
        result
    }

    fn tuple_variant<V>(self, len: usize, visitor: V) -> DecodeResult<V::Value>
    where
        V: Visitor<'de>,
    {
        self.de.deserialize_fixed_size_array(len, visitor)
    }

    fn struct_variant<V>(
        self,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> DecodeResult<V::Value>
    where
        V: Visitor<'de>,
    {
        de::Deserializer::deserialize_map(&mut *self.de, visitor)
    }
}

#[cfg(test)]
mod tests {
    use std::fmt;

    use serde::de::{DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
    use serde::Deserialize;

    use crate::{deserialize_any_with_raw_strings, MaxMindDbError, Reader};

    use super::{Decoder, VerificationState};

    #[derive(Debug, PartialEq)]
    enum RawValue<'de> {
        String(&'de [u8]),
        Bytes(&'de [u8]),
        Bool(bool),
        I32(i32),
        U16(u16),
        U32(u32),
        U64(u64),
        U128(u128),
        F32(f32),
        F64(f64),
        Array(Vec<RawValue<'de>>),
        Map(Vec<(Vec<u8>, RawValue<'de>)>),
    }

    impl<'de> Deserialize<'de> for RawValue<'de> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            RawValueSeed.deserialize(deserializer)
        }
    }

    struct RawValueSeed;

    impl<'de> DeserializeSeed<'de> for RawValueSeed {
        type Value = RawValue<'de>;

        fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserialize_any_with_raw_strings(deserializer, RawValueVisitor)
        }
    }

    struct RawValueVisitor;

    impl<'de> Visitor<'de> for RawValueVisitor {
        type Value = RawValue<'de>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("an MMDB value")
        }

        fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_bytes(RawStringVisitor)
        }

        fn visit_borrowed_bytes<E>(self, bytes: &'de [u8]) -> Result<Self::Value, E> {
            Ok(RawValue::Bytes(bytes))
        }

        fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
            Ok(RawValue::Bool(value))
        }

        fn visit_i32<E>(self, value: i32) -> Result<Self::Value, E> {
            Ok(RawValue::I32(value))
        }

        fn visit_u16<E>(self, value: u16) -> Result<Self::Value, E> {
            Ok(RawValue::U16(value))
        }

        fn visit_u32<E>(self, value: u32) -> Result<Self::Value, E> {
            Ok(RawValue::U32(value))
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
            Ok(RawValue::U64(value))
        }

        fn visit_u128<E>(self, value: u128) -> Result<Self::Value, E> {
            Ok(RawValue::U128(value))
        }

        fn visit_f32<E>(self, value: f32) -> Result<Self::Value, E> {
            Ok(RawValue::F32(value))
        }

        fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E> {
            Ok(RawValue::F64(value))
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut entries = Vec::with_capacity(map.size_hint().unwrap_or(0));
            while let Some(key) = map.next_key_seed(RawIdentifierSeed)? {
                let value = map.next_value_seed(RawValueSeed)?;
                entries.push((key, value));
            }
            Ok(RawValue::Map(entries))
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0));
            while let Some(value) = sequence.next_element_seed(RawValueSeed)? {
                values.push(value);
            }
            Ok(RawValue::Array(values))
        }
    }

    struct RawStringVisitor;

    impl<'de> Visitor<'de> for RawStringVisitor {
        type Value = RawValue<'de>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("borrowed MMDB string bytes")
        }

        fn visit_borrowed_bytes<E>(self, bytes: &'de [u8]) -> Result<Self::Value, E> {
            Ok(RawValue::String(bytes))
        }
    }

    #[derive(Clone, Copy)]
    struct RawIdentifierSeed;

    impl<'de> DeserializeSeed<'de> for RawIdentifierSeed {
        type Value = Vec<u8>;

        fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_identifier(RawIdentifierVisitor)
        }
    }

    struct RawIdentifierVisitor;

    impl<'de> Visitor<'de> for RawIdentifierVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("borrowed MMDB map-key bytes")
        }

        fn visit_borrowed_bytes<E>(self, bytes: &'de [u8]) -> Result<Self::Value, E> {
            Ok(bytes.to_vec())
        }
    }

    struct AnyIdentifierSeed;

    impl<'de> DeserializeSeed<'de> for AnyIdentifierSeed {
        type Value = usize;

        fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_any(AnyIdentifierVisitor)
        }
    }

    struct AnyIdentifierVisitor;

    impl<'de> Visitor<'de> for AnyIdentifierVisitor {
        type Value = usize;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("an MMDB map key")
        }

        fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E> {
            Ok(value.len())
        }

        fn visit_borrowed_bytes<E>(self, value: &'de [u8]) -> Result<Self::Value, E> {
            Ok(value.len())
        }
    }

    #[derive(Debug, PartialEq)]
    struct AnyKeyMap(usize);

    struct AnyKeyMapVisitor;

    impl<'de> Visitor<'de> for AnyKeyMapVisitor {
        type Value = AnyKeyMap;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("an MMDB map")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut count = 0;
            while let Some(key_size) = map.next_key_seed(AnyIdentifierSeed)? {
                assert_eq!(key_size, 4096);
                map.next_value::<serde::de::IgnoredAny>()?;
                count += 1;
            }
            Ok(AnyKeyMap(count))
        }
    }

    #[allow(dead_code)]
    #[derive(Debug)]
    struct OwnedBytes(Vec<u8>);

    impl<'de> Deserialize<'de> for OwnedBytes {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_byte_buf(OwnedBytesVisitor)
        }
    }

    struct OwnedBytesVisitor;

    impl<'de> Visitor<'de> for OwnedBytesVisitor {
        type Value = OwnedBytes;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("an MMDB byte value")
        }

        fn visit_borrowed_bytes<E>(self, value: &'de [u8]) -> Result<Self::Value, E> {
            Ok(OwnedBytes(value.to_vec()))
        }

        fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E> {
            Ok(OwnedBytes(value))
        }
    }

    #[test]
    fn raw_string_mode_distinguishes_strings_from_bytes() {
        let mut string_decoder = Decoder::new(&[0x42, 0xff, 0xfe], 0);
        let string = RawValueSeed.deserialize(&mut string_decoder).unwrap();
        assert_eq!(string, RawValue::String(&[0xff, 0xfe]));

        let mut bytes_decoder = Decoder::new(&[0x82, 0xff, 0xfe], 0);
        let bytes = RawValueSeed.deserialize(&mut bytes_decoder).unwrap();
        assert_eq!(bytes, RawValue::Bytes(&[0xff, 0xfe]));
    }

    #[test]
    fn raw_string_mode_recurses_through_maps() {
        let encoded = [
            0x02, 0x00, // map with two entries
            0x44, b't', b'e', b'x', b't', // "text"
            0x41, 0xff, // invalid UTF-8 string value
            0x44, b'b', b'l', b'o', b'b', // "blob"
            0x81, 0xff, // byte value
        ];
        let mut decoder = Decoder::new(&encoded, 0);

        let value = RawValueSeed.deserialize(&mut decoder).unwrap();

        assert_eq!(
            value,
            RawValue::Map(vec![
                (b"text".to_vec(), RawValue::String(&[0xff])),
                (b"blob".to_vec(), RawValue::Bytes(&[0xff])),
            ])
        );
    }

    #[test]
    fn raw_string_mode_recurses_through_arrays_and_pointers() {
        let encoded_array = [
            0x02, 0x04, // array with two elements
            0x41, 0xff, // invalid UTF-8 string value
            0x81, 0xff, // byte value
        ];
        let mut array_decoder = Decoder::new(&encoded_array, 0);
        let array = RawValueSeed.deserialize(&mut array_decoder).unwrap();
        assert_eq!(
            array,
            RawValue::Array(vec![RawValue::String(&[0xff]), RawValue::Bytes(&[0xff]),])
        );

        let encoded_pointer = [
            0x20, 0x02, // pointer to offset two
            0x41, 0xff, // invalid UTF-8 string value
        ];
        let mut pointer_decoder = Decoder::new(&encoded_pointer, 0);
        let pointer = RawValueSeed.deserialize(&mut pointer_decoder).unwrap();
        assert_eq!(pointer, RawValue::String(&[0xff]));
    }

    #[test]
    fn raw_string_mode_restores_pointer_continuation_in_maps() {
        let encoded = [
            0x02, 0x00, // map with two entries
            0x41, b'a', // "a"
            0x20, 0x0a, // pointer to the string at offset ten
            0x41, b'b', // "b"
            0x41, b'y', // "y"
            0x41, b'x', // pointed-to string "x"
        ];
        let mut decoder = Decoder::new(&encoded, 0);

        let value = RawValueSeed.deserialize(&mut decoder).unwrap();

        assert_eq!(
            value,
            RawValue::Map(vec![
                (b"a".to_vec(), RawValue::String(b"x")),
                (b"b".to_vec(), RawValue::String(b"y")),
            ])
        );
    }

    #[test]
    fn raw_string_mode_decodes_all_scalar_types() {
        let mut encoded = vec![0x08, 0x00]; // map with eight entries

        encoded.extend_from_slice(&[0x41, b'd', 0x68]);
        encoded.extend_from_slice(&1.5_f64.to_be_bytes());
        encoded.extend_from_slice(&[0x41, b's', 0xa2, 0x01, 0x02]);
        encoded.extend_from_slice(&[0x41, b'i', 0xc4, 0x01, 0x02, 0x03, 0x04]);
        encoded.extend_from_slice(&[0x41, b'n', 0x04, 0x01]);
        encoded.extend_from_slice(&(-2_i32).to_be_bytes());
        encoded.extend_from_slice(&[0x41, b'l', 0x08, 0x02]);
        encoded.extend_from_slice(&0x0102_0304_0506_0708_u64.to_be_bytes());
        encoded.extend_from_slice(&[0x41, b'x', 0x10, 0x03]);
        encoded.extend_from_slice(&0x0102_0304_0506_0708_1112_1314_1516_1718_u128.to_be_bytes());
        encoded.extend_from_slice(&[0x41, b'b', 0x01, 0x07]);
        encoded.extend_from_slice(&[0x41, b'f', 0x04, 0x08]);
        encoded.extend_from_slice(&2.5_f32.to_be_bytes());

        let mut decoder = Decoder::new(&encoded, 0);
        let value = RawValueSeed.deserialize(&mut decoder).unwrap();

        assert_eq!(
            value,
            RawValue::Map(vec![
                (b"d".to_vec(), RawValue::F64(1.5)),
                (b"s".to_vec(), RawValue::U16(0x0102)),
                (b"i".to_vec(), RawValue::U32(0x0102_0304)),
                (b"n".to_vec(), RawValue::I32(-2)),
                (b"l".to_vec(), RawValue::U64(0x0102_0304_0506_0708)),
                (
                    b"x".to_vec(),
                    RawValue::U128(0x0102_0304_0506_0708_1112_1314_1516_1718)
                ),
                (b"b".to_vec(), RawValue::Bool(true)),
                (b"f".to_vec(), RawValue::F32(2.5)),
            ])
        );
    }

    #[test]
    fn raw_string_mode_rejects_excessive_pointer_depth_and_unknown_types() {
        run_on_bounded_stack(|| {
            let mut cyclic_decoder = Decoder::new(&[0x20, 0x00], 0);
            let depth_err = RawValueSeed.deserialize(&mut cyclic_decoder).unwrap_err();
            assert!(depth_err
                .to_string()
                .contains("exceeded maximum data structure depth"));
        });

        let mut unknown_decoder = Decoder::new(&[0x00, 0x06], 0);
        let type_err = RawValueSeed.deserialize(&mut unknown_decoder).unwrap_err();
        assert!(type_err.to_string().contains("unknown data type: 13"));
    }

    #[test]
    fn malformed_extended_types_return_errors_instead_of_overflowing() {
        for extended_type in 249..=u8::MAX {
            let encoded = [0x00, extended_type];
            let mut decoder = Decoder::new(&encoded, 0);
            let error = RawValueSeed.deserialize(&mut decoder).unwrap_err();

            assert!(matches!(*error, MaxMindDbError::InvalidDatabase { .. }));
            assert!(error.to_string().contains(&format!(
                "unknown data type: {}",
                u16::from(extended_type) + 7
            )));

            let mut typed_decoder = Decoder::new(&encoded, 0);
            let typed_error =
                <u32 as serde::Deserialize>::deserialize(&mut typed_decoder).unwrap_err();
            assert!(matches!(
                *typed_error,
                MaxMindDbError::InvalidDatabase { .. }
            ));
        }
    }

    #[test]
    fn nested_values_without_raw_opt_in_use_normal_string_decoding() {
        struct NestedNormalVisitor;

        impl<'de> Visitor<'de> for NestedNormalVisitor {
            type Value = &'de str;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an MMDB map containing a string")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let Some(_key) = map.next_key_seed(RawIdentifierSeed)? else {
                    return Err(serde::de::Error::custom("expected one map entry"));
                };
                map.next_value::<&'de str>()
            }
        }

        let encoded = [
            0x01, 0x00, // map with one entry
            0x41, b'k', // "k"
            0x45, b'h', b'e', b'l', b'l', b'o', // "hello"
        ];
        let mut decoder = Decoder::new(&encoded, 0);
        let value = deserialize_any_with_raw_strings(&mut decoder, NestedNormalVisitor).unwrap();

        assert_eq!(value, "hello");
    }

    fn raw_map_value<'value, 'de>(
        value: &'value RawValue<'de>,
        key: &[u8],
    ) -> &'value RawValue<'de> {
        let RawValue::Map(entries) = value else {
            panic!("expected map, got {value:?}");
        };
        entries
            .iter()
            .find_map(|(entry_key, value)| (entry_key == key).then_some(value))
            .unwrap_or_else(|| panic!("missing map key {:?}", String::from_utf8_lossy(key)))
    }

    #[test]
    fn raw_string_mode_decodes_reader_lookup_results() {
        let reader = Reader::open_readfile("test-data/test-data/GeoIP2-City-Test.mmdb").unwrap();
        let lookup = reader.lookup("89.160.20.128".parse().unwrap()).unwrap();
        let value = lookup.decode::<RawValue<'_>>().unwrap().unwrap();

        let city = raw_map_value(&value, b"city");
        let city_names = raw_map_value(city, b"names");
        assert_eq!(
            raw_map_value(city_names, b"en"),
            &RawValue::String("Linköping".as_bytes())
        );

        let country = raw_map_value(&value, b"country");
        assert_eq!(
            raw_map_value(country, b"is_in_european_union"),
            &RawValue::Bool(true)
        );

        let location = raw_map_value(&value, b"location");
        assert_eq!(
            raw_map_value(location, b"accuracy_radius"),
            &RawValue::U16(76)
        );
        assert_eq!(
            raw_map_value(location, b"latitude"),
            &RawValue::F64(58.4167)
        );

        let subdivisions = raw_map_value(&value, b"subdivisions");
        let RawValue::Array(subdivisions) = subdivisions else {
            panic!("expected subdivisions array, got {subdivisions:?}");
        };
        assert!(!subdivisions.is_empty());
    }

    #[test]
    fn ordinary_string_decoding_remains_validated() {
        // The old handwritten visitor accepted visit_borrowed_str directly
        // and hid the missing visit_newtype_struct callback.
        #[derive(Debug, Deserialize, PartialEq)]
        struct Ordinary<'a>(&'a str);

        #[derive(Debug, Deserialize, PartialEq)]
        struct Owned(String);

        let mut valid_decoder = Decoder::new(&[0x45, b'h', b'e', b'l', b'l', b'o'], 0);
        assert_eq!(String::deserialize(&mut valid_decoder).unwrap(), "hello");

        let mut newtype_decoder = Decoder::new(&[0x45, b'h', b'e', b'l', b'l', b'o'], 0);
        assert_eq!(
            Ordinary::deserialize(&mut newtype_decoder).unwrap(),
            Ordinary("hello")
        );

        let mut owned_decoder = Decoder::new(&[0x45, b'h', b'e', b'l', b'l', b'o'], 0);
        assert_eq!(
            Owned::deserialize(&mut owned_decoder).unwrap(),
            Owned("hello".to_owned())
        );

        #[cfg(not(feature = "unsafe-str-decode"))]
        {
            let mut invalid_decoder = Decoder::new(&[0x41, 0xff], 0);
            let err = String::deserialize(&mut invalid_decoder).unwrap_err();
            assert!(err.to_string().contains("invalid UTF-8"));

            let mut invalid_decoder = Decoder::new(&[0x41, 0xff], 0);
            let err = Ordinary::deserialize(&mut invalid_decoder).unwrap_err();
            assert!(err.to_string().contains("invalid UTF-8"));

            let mut invalid_decoder = Decoder::new(&[0x41, 0xff], 0);
            let err = Owned::deserialize(&mut invalid_decoder).unwrap_err();
            assert!(err.to_string().contains("invalid UTF-8"));
        }
    }

    #[test]
    fn test_decoder_accepts_tuple_with_matching_length() {
        #[derive(Debug, serde::Deserialize)]
        struct TupleRecord {
            array: (u32, u32, u32),
        }

        #[derive(Debug, serde::Deserialize)]
        struct TupleStructRecord {
            array: TupleStruct,
        }

        #[derive(Debug, serde::Deserialize)]
        struct TupleStruct(u32, u32, u32);

        let reader =
            Reader::open_readfile("test-data/test-data/MaxMind-DB-test-decoder.mmdb").unwrap();
        let lookup = reader.lookup("1.1.1.0".parse().unwrap()).unwrap();

        let tuple = lookup.decode::<TupleRecord>().unwrap().unwrap();
        assert_eq!(tuple.array, (1, 2, 3));

        let tuple_struct = lookup.decode::<TupleStructRecord>().unwrap().unwrap();
        assert_eq!(tuple_struct.array.0, 1);
        assert_eq!(tuple_struct.array.1, 2);
        assert_eq!(tuple_struct.array.2, 3);
    }

    #[test]
    fn test_decoder_rejects_tuple_length_mismatch() {
        #[allow(dead_code)]
        #[derive(Debug, serde::Deserialize)]
        struct TupleRecord {
            array: (u32, u32),
        }

        #[allow(dead_code)]
        #[derive(Debug, serde::Deserialize)]
        struct TupleStructRecord {
            array: TupleStruct,
        }

        #[allow(dead_code)]
        #[derive(Debug, serde::Deserialize)]
        struct TupleStruct(u32, u32);

        let reader =
            Reader::open_readfile("test-data/test-data/MaxMind-DB-test-decoder.mmdb").unwrap();
        let lookup = reader.lookup("1.1.1.0".parse().unwrap()).unwrap();

        let tuple_err = lookup.decode::<TupleRecord>().unwrap_err();
        assert!(tuple_err
            .to_string()
            .contains("expected tuple of length 2, got array of length 3"));

        let tuple_struct_err = lookup.decode::<TupleStructRecord>().unwrap_err();
        assert!(tuple_struct_err
            .to_string()
            .contains("expected tuple of length 2, got array of length 3"));
    }

    #[test]
    fn test_skip_value_for_verification_rejects_truncated_pointer_payload() {
        let mut decoder = Decoder::new(&[0x28], 0);
        let err = decoder
            .skip_value_for_verification(&mut VerificationState::new(decoder.limit))
            .unwrap_err();

        assert!(matches!(*err, MaxMindDbError::InvalidDatabase { .. }));
    }

    #[test]
    fn four_byte_pointers_ignore_low_control_bits() {
        for ctrl_byte in 0x38..=0x3f {
            let buf = [
                ctrl_byte, 0, 0, 0, 7, // four-byte pointer to offset seven
                0xa1, 42, // next inline uint16
                0xa1, 99, // pointed-to uint16
            ];
            let mut decoder = Decoder::new(&buf, 0);
            assert_eq!(u16::deserialize(&mut decoder).unwrap(), 99);
            assert_eq!(decoder.offset(), 5);
            assert_eq!(u16::deserialize(&mut decoder).unwrap(), 42);

            let mut decoder = Decoder::new(&buf, 0);
            assert_eq!(serde_json::Value::deserialize(&mut decoder).unwrap(), 99);
            assert_eq!(decoder.offset(), 5);
        }
    }

    #[test]
    fn four_byte_pointers_ignore_low_control_bits_in_keys_and_skips() {
        #[derive(Deserialize)]
        struct Record {
            a: u16,
        }

        for ctrl_byte in 0x38..=0x3f {
            let buf = [
                0xe2, // map with two entries
                ctrl_byte, 0, 0, 0, 15, // key: four-byte pointer to "a"
                0xa1, 42, // value: inline uint16
                0x41, b'x', // key: inline "x"
                ctrl_byte, 0, 0, 0, 17, // value: four-byte pointer to uint16
                0x41, b'a', // offset 15
                0xa1, 99, // offset 17
            ];

            // Map keys go through try_read_identifier_bytes, and the unknown
            // field "x" goes through skip_value.
            let mut decoder = Decoder::new(&buf, 0);
            assert_eq!(Record::deserialize(&mut decoder).unwrap().a, 42);
            assert_eq!(decoder.offset(), 15);

            let mut decoder = Decoder::new(&buf, 1);
            let (charged, cached) = decoder.count_payload_at_current().unwrap();
            assert!(charged);
            let cached = cached.unwrap();
            assert_eq!(cached.bytes, b"a");
            assert_eq!(cached.continuation, 6);
            assert_eq!(decoder.offset(), 1);

            let mut decoder = Decoder::new(&buf, 0);
            decoder
                .skip_value_for_verification(&mut VerificationState::new(decoder.limit))
                .unwrap();
            assert_eq!(decoder.offset(), 15);
        }
    }

    #[test]
    fn pointer_widths_preserve_offsets_and_decoder_limits() {
        let cases: &[(usize, &[u8], usize)] = &[
            (0x00, &[0x00], 0),
            (0x07, &[0xff], 2_047),
            (0x08, &[0x00, 0x00], 2_048),
            (0x0f, &[0xff, 0xff], 526_335),
            (0x10, &[0x00, 0x00, 0x00], 526_336),
            (0x10, &[0x01, 0x02, 0x03], 592_387),
            (0x17, &[0xff, 0xff, 0xff], 134_744_063),
            (0x18, &[0x00, 0x00, 0x00, 0x00], 0),
            (0x1f, &[0xff, 0xff, 0xff, 0xff], 4_294_967_295),
        ];
        for &(size, payload, target) in cases {
            let mut buf = vec![0];
            buf.extend_from_slice(payload);
            let continuation = buf.len();
            buf.extend([0xa1, 42]);
            let mut decoder = Decoder::new(&buf, 1);
            assert_eq!(decoder.decode_pointer(size), target);
            assert_eq!(decoder.offset(), continuation);
            assert_eq!(u16::deserialize(&mut decoder).unwrap(), 42);

            for limit in 1..continuation {
                let mut decoder = Decoder::new_with_limit(&buf, 1, limit);
                assert_eq!(decoder.decode_pointer(size), limit);
                assert_eq!(decoder.offset(), limit);
                assert!(u16::deserialize(&mut decoder).is_err());
            }
        }
    }

    fn compare_key_decoders(buf: &[u8], start: usize, limit: usize, remaining: u32) {
        for budgeted in [false, true] {
            let mut fast = Decoder::new_with_limit(buf, start, limit);
            let mut general = Decoder::new_with_limit(buf, start, limit);
            if budgeted {
                fast.activate_budget();
                general.activate_budget();
            }
            fast.payload_remaining = remaining;
            general.payload_remaining = remaining;
            let actual = fast.read_str_as_bytes().map_err(|e| format!("{e:?}"));
            let expected = general
                .read_str_as_bytes_slow()
                .map_err(|e| format!("{e:?}"));
            assert_eq!(
                actual, expected,
                "start={start}, limit={limit}, remaining={remaining}, budgeted={budgeted}"
            );
            assert_eq!(fast.current_ptr, general.current_ptr);
            assert_eq!(fast.state, general.state);
            assert_eq!(fast.payload_remaining, general.payload_remaining);
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "too slow under Miri")]
    fn key_decoding_preserves_values_errors_cursors_and_budgets() {
        let mut buf = [0x61; 80];
        buf[..2].copy_from_slice(&[0x20, 10]);
        for control in 0..=255 {
            buf[10] = control;
            for limit in 0..=buf.len() {
                for remaining in [0, 1, 2, 28, 29, 4096] {
                    compare_key_decoders(&buf, 0, limit, remaining);
                    compare_key_decoders(&buf, 10, limit, remaining);
                }
            }
        }

        for pointer in 0..2048 {
            let mut buf = [0x61; 2112];
            buf[2080..2082].copy_from_slice(&[0x20 | ((pointer >> 8) as u8), pointer as u8]);
            // Raw keys need not be valid UTF-8. Keep the pointer token after
            // every possible target so it cannot overlap the string payload.
            buf[pointer..pointer + 3].copy_from_slice(&[0x42, 0xFF, 0xFE]);
            compare_key_decoders(&buf, 2080, buf.len(), 1);
            compare_key_decoders(&buf, 2080, buf.len(), 2);
        }
    }

    // Kept out of the exhaustive test above so Miri still checks the
    // unchecked reads at the buffer edges, on fewer random buffers.
    #[test]
    fn key_decoding_preserves_edge_cursors_on_random_buffers() {
        let rounds = if cfg!(miri) { 4 } else { 8192 };
        let mut buf = [0; 80];
        let mut state = 0x4D59_5DF4_D0F3_3173_u64;
        for _ in 0..rounds {
            for byte in &mut buf {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                *byte = (state >> 32) as u8;
            }
            for start in [0, 1, 10, 79, 80, usize::MAX] {
                compare_key_decoders(&buf, start, buf.len(), 0);
                compare_key_decoders(&buf, start, buf.len(), 4096);
            }
        }
    }

    // Each control byte as the last or second-to-last byte, where a read past
    // the limit would leave the buffer. Small enough to run under Miri.
    #[test]
    fn key_decoding_handles_every_control_byte_at_the_buffer_end() {
        let mut buf = [0x61; 80];
        for control in 0..=255 {
            for start in [78, 79] {
                buf[start] = control;
                compare_key_decoders(&buf, start, buf.len(), 4096);
                buf[start] = 0x61;
            }
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "too slow under Miri")]
    fn key_decoders_agree_on_pointer_widths_and_extended_strings() {
        let pointers: &[(&[u8], usize)] = &[
            (&[0x20, 8], 8),
            (&[0x28, 0, 0], 2048),
            (&[0x30, 0, 0, 0], 526_336),
            (&[0x38, 0, 0, 0, 8], 8),
        ];
        for &(pointer, target) in pointers {
            for size in [0, 1, 28, 29, 285] {
                let mut buf = pointer.to_vec();
                buf.resize(target, 0);
                match size {
                    0..=28 => buf.push(0x40 | size as u8),
                    29 => buf.extend_from_slice(&[0x5D, 0]),
                    285 => buf.extend_from_slice(&[0x5E, 0, 0]),
                    _ => unreachable!(),
                }
                buf.resize(buf.len() + size, b'k');
                for limit in [pointer.len() - 1, target, buf.len() - 1, buf.len()] {
                    for remaining in [0, 28, 4096] {
                        compare_key_decoders(&buf, 0, limit, remaining);
                    }
                }
            }
        }
    }

    #[test]
    fn typed_pointer_errors_restore_continuation_and_depth() {
        let targets: &[&[u8]] = &[
            &[],           // Missing target header.
            &[0x5d],       // Truncated extended string length.
            &[0xc0],       // Wrong type: uint32 instead of string.
            &[0x20, 0],    // Pointer to another pointer.
            &[0x41],       // Truncated string payload.
            &[0x41, b'x'], // Valid string.
        ];
        for &target in targets {
            let mut buf = vec![0x20, 4, 0xa1, 42];
            buf.extend_from_slice(target);
            let mut decoder = Decoder::new(&buf, 0);
            let result = <&str>::deserialize(&mut decoder);
            if target == [0x41, b'x'] {
                assert_eq!(result.unwrap(), "x");
            } else {
                assert!(result.is_err());
            }
            assert_eq!(decoder.offset(), 2);
            assert_eq!(decoder.state & super::DEPTH_MASK, 0);
            assert_eq!(u16::deserialize(&mut decoder).unwrap(), 42);
        }
    }

    #[test]
    fn typed_pointer_depth_limit_restores_continuation() {
        let buf = [0x20, 4, 0xa1, 42, 0x41, b'x'];
        let mut decoder = Decoder::new(&buf, 0);
        for _ in 0..super::MAXIMUM_DATA_STRUCTURE_DEPTH {
            decoder.enter_nested().unwrap();
        }

        let error = <&str>::deserialize(&mut decoder).unwrap_err();
        assert!(matches!(
            *error,
            MaxMindDbError::InvalidDatabase {
                offset: Some(4),
                ..
            }
        ));
        assert!(error
            .to_string()
            .contains("exceeded maximum data structure depth"));
        assert_eq!(decoder.offset(), 2);
        assert_eq!(
            decoder.state & super::DEPTH_MASK,
            u32::from(super::MAXIMUM_DATA_STRUCTURE_DEPTH)
        );
        assert_eq!(u16::deserialize(&mut decoder).unwrap(), 42);
    }

    #[cfg(not(feature = "unsafe-str-decode"))]
    #[test]
    #[cfg_attr(miri, ignore = "too slow under Miri")]
    fn ascii_check_covers_every_byte_at_word_boundaries() {
        for len in 0..=80 {
            let mut storage = vec![0x7f; len + 7];
            for offset in 0..8 {
                let bytes = &mut storage[offset..offset + len];
                assert!(super::is_ascii(bytes));
                for index in 0..len {
                    for byte in 0x80..=0xff {
                        bytes[index] = byte;
                        assert!(
                            !super::is_ascii(bytes),
                            "accepted non-ASCII byte {byte} at index {index}, length {len}, offset {offset}"
                        );
                    }
                    bytes[index] = 0x7f;
                }
            }
        }
    }

    #[test]
    fn ignored_any_skips_pointer_targets_but_verification_follows_them() {
        for (pointer_size, control) in [(1, 0x20), (2, 0x28), (3, 0x30), (4, 0x38)] {
            // Each pointer targets a location outside this buffer. Skipping
            // must resume at the next value without expanding that target.
            let mut encoded = vec![control];
            encoded.resize(pointer_size + 1, 0xff);
            let continuation = encoded.len();
            encoded.extend([0xa1, 42]); // uint16 with a one-byte payload
            let mut decoder = Decoder::new(&encoded, 0);
            serde::de::IgnoredAny::deserialize(&mut decoder).unwrap();
            assert_eq!(decoder.offset(), continuation);
            assert_eq!(u16::deserialize(&mut decoder).unwrap(), 42);
            assert_eq!(decoder.offset(), encoded.len());

            let mut decoder = Decoder::new(&encoded, 0);
            let err = decoder
                .skip_value_for_verification(&mut VerificationState::new(decoder.limit))
                .unwrap_err();
            assert!(matches!(*err, MaxMindDbError::InvalidDatabase { .. }));

            // Every truncated payload must fail without advancing beyond the
            // header, even when bytes exist outside the decoder's limit.
            for limit in 1..continuation {
                for buf in [&encoded[..limit], &encoded[..]] {
                    let mut decoder = Decoder::new_with_limit(buf, 0, limit);
                    let err = serde::de::IgnoredAny::deserialize(&mut decoder).unwrap_err();
                    assert!(matches!(
                        *err,
                        MaxMindDbError::InvalidDatabase { message, offset: Some(1) }
                            if message == format!("pointer of size {pointer_size}")
                    ));
                    assert_eq!(decoder.offset(), 1);
                }
            }
        }
    }

    #[test]
    fn test_decoder_caps_impossible_container_size_hint() {
        // Extended array with 284 declared elements and no element payload.
        let mut decoder = Decoder::new(&[0x1d, 0x04, 0xff], 0);
        let err = Vec::<serde::de::IgnoredAny>::deserialize(&mut decoder).unwrap_err();

        assert!(matches!(*err, MaxMindDbError::InvalidDatabase { .. }));
        assert!(err.to_string().contains("unexpected end of buffer"));
    }

    #[test]
    fn ignored_any_rejects_excessive_inline_container_work() {
        // Extended array with 65,536 declared elements and no payload. An
        // ignored inline container still requires one loop iteration per
        // child, so it shares the logical-value operation budget.
        let mut decoder = Decoder::new(&[0x1e, 0x04, 0xfe, 0xe3], 0);
        let err = serde::de::IgnoredAny::deserialize(&mut decoder).unwrap_err();

        assert!(err
            .to_string()
            .contains("maximum number of data structure values"));
    }

    #[test]
    fn ignored_any_rejects_excessive_inline_map_work() {
        // A 32,768-entry map contains 65,536 children in addition to the map
        // itself, so it cannot fit within the logical-value operation budget.
        let mut decoder = Decoder::new(&[0xfe, 0x7e, 0xe3], 0);
        let err = serde::de::IgnoredAny::deserialize(&mut decoder).unwrap_err();

        assert!(matches!(*err, MaxMindDbError::ResourceLimit { .. }));
        assert!(err
            .to_string()
            .contains("maximum number of data structure values"));
    }

    #[test]
    fn navigation_rejects_excessive_declared_container_work() {
        let mut decoder = Decoder::new(&[0x1e, 0x04, 0xfe, 0xe3], 0);
        let err = decoder.consume_container_header().unwrap_err();

        assert!(err
            .to_string()
            .contains("maximum number of data structure values"));
    }

    #[test]
    fn oversized_containers_fail_before_visitor_entry() {
        use std::cell::Cell;

        struct EntryVisitor<'a>(&'a Cell<bool>);
        impl<'de> Visitor<'de> for EntryVisitor<'_> {
            type Value = ();

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a container")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, _: A) -> Result<(), A::Error> {
                self.0.set(true);
                Ok(())
            }

            fn visit_map<A: MapAccess<'de>>(self, _: A) -> Result<(), A::Error> {
                self.0.set(true);
                Ok(())
            }
        }

        let mut array = vec![0x1e, 0x04, 0xfe, 0xe3]; // 65,536 elements
        array.extend([0x00, 0x07].repeat(65_536)); // false
        let mut map = vec![0xfe, 0x7e, 0xe3]; // 32,768 entries
        map.extend([0x40, 0x00, 0x07].repeat(32_768)); // empty string => false

        // Complete payloads leave room for a large size hint. Neither concrete
        // nor dynamic entry points may expose it to a visitor before rejecting.
        for (is_map, bytes) in [(false, array), (true, map)] {
            for dynamic in [false, true] {
                let entered = Cell::new(false);
                let mut decoder = Decoder::new(&bytes, 0);
                let visitor = EntryVisitor(&entered);
                let result = if dynamic {
                    decoder.deserialize_any(visitor)
                } else if is_map {
                    decoder.deserialize_map(visitor)
                } else {
                    decoder.deserialize_seq(visitor)
                };
                assert!(matches!(
                    result.map_err(|error| *error),
                    Err(MaxMindDbError::ResourceLimit { .. })
                ));
                assert!(
                    !entered.get(),
                    "visitor entered: map={is_map}, dynamic={dynamic}"
                );
            }
        }
    }

    #[test]
    fn city_subdivisions_reject_declared_size_before_allocating() {
        // Extended array with 65,536 elements and no payload. Concrete Vec
        // decoding must reject its declared children before Serde sees the
        // size hint and can allocate for them.
        let mut decoder = Decoder::new(&[0x1e, 0x04, 0xfe, 0xe3], 0);
        let err =
            Vec::<crate::geoip2::city::Subdivision<'_>>::deserialize(&mut decoder).unwrap_err();

        assert!(matches!(*err, MaxMindDbError::ResourceLimit { .. }));
        assert!(err
            .to_string()
            .contains("maximum number of data structure values"));
    }

    #[test]
    fn concrete_map_rejects_declared_size_before_allocating() {
        // Extended map with 32,768 entries and no payload. Map children include
        // both keys and values, so this exceeds the 65,536-value operation
        // budget once the top-level map itself is included. The rejection must
        // happen before HashMap receives a size hint and can allocate.
        let mut decoder = Decoder::new(&[0xfe, 0x7e, 0xe3], 0);
        let err =
            std::collections::HashMap::<String, serde::de::IgnoredAny>::deserialize(&mut decoder)
                .unwrap_err();

        assert!(matches!(*err, MaxMindDbError::ResourceLimit { .. }));
        assert!(err
            .to_string()
            .contains("maximum number of data structure values"));
    }

    #[test]
    #[cfg_attr(miri, ignore = "too slow under Miri")]
    fn concrete_sequence_charges_repeated_shared_struct_maps() {
        #[derive(Debug, Deserialize)]
        struct EmptyRecord {}

        // A shared 200-entry map followed by an array of 300 pointers to that
        // map. Every map entry is unknown to EmptyRecord. Ignoring its value is
        // cheap, but the requested struct still has to examine every key each
        // time the pointer target is decoded. Aggregate container reservation
        // rejects that fan-out after bounded work.
        let mut buf = vec![0xfd, 171]; // map size: 29 + 171 = 200
        for _ in 0..200 {
            buf.extend_from_slice(&[0x40, 0xe0]); // empty string => empty map
        }
        let array_offset = buf.len();
        buf.extend_from_slice(&[0x1e, 0x04, 0x00, 0x0f]); // array size: 300
        for _ in 0..300 {
            append_pointer(&mut buf, 0);
        }

        let mut decoder = Decoder::new(&buf, array_offset);
        let err = Vec::<EmptyRecord>::deserialize(&mut decoder).unwrap_err();

        assert!(matches!(*err, MaxMindDbError::ResourceLimit { .. }));
        assert!(err
            .to_string()
            .contains("maximum number of data structure values"));
    }

    #[test]
    #[cfg_attr(miri, ignore = "too slow under Miri")]
    fn concrete_sequence_charges_repeated_string_payloads() {
        // One 4 KiB string followed by an array of 600 pointers to it. The
        // array activates the operation budget, and direct &str decoding must
        // recharge the shared payload for every logical occurrence.
        let (buf, array_offset) = repeated_4k_payload_array(0x5e, 600);

        let mut decoder = Decoder::new(&buf, array_offset);
        let err = Vec::<&str>::deserialize(&mut decoder).unwrap_err();

        assert!(matches!(*err, MaxMindDbError::ResourceLimit { .. }));
        assert!(err
            .to_string()
            .contains("maximum size of data structure string and bytes"));
    }

    #[test]
    fn direct_byte_buf_decoding_charges_repeated_payloads() {
        let (buf, array_offset) = repeated_4k_payload_array(0x9e, 600);
        let mut decoder = Decoder::new(&buf, array_offset);
        let err = Vec::<OwnedBytes>::deserialize(&mut decoder).unwrap_err();

        assert!(matches!(*err, MaxMindDbError::ResourceLimit { .. }));
        assert!(err
            .to_string()
            .contains("maximum size of data structure string and bytes"));
    }

    #[test]
    fn raw_string_decoding_charges_repeated_payloads() {
        let (buf, array_offset) = repeated_4k_payload_array(0x5e, 600);
        let mut decoder = Decoder::new(&buf, array_offset);
        let err = RawValueSeed.deserialize(&mut decoder).unwrap_err();

        assert!(matches!(*err, MaxMindDbError::ResourceLimit { .. }));
        assert!(err
            .to_string()
            .contains("maximum size of data structure string and bytes"));
    }

    #[derive(Debug, Deserialize)]
    enum StandaloneScalarEnum {
        Known,
    }

    fn large_string(size: usize) -> Vec<u8> {
        assert!((65_821..=65_821 + 0xff_ff_ff).contains(&size));
        let encoded_size = (size - 65_821) as u32;
        let mut buf = vec![0x5f]; // string with a three-byte extended size
        buf.extend_from_slice(&encoded_size.to_be_bytes()[1..]);
        buf.resize(buf.len() + size, b'a');
        buf
    }

    #[test]
    #[cfg_attr(miri, ignore = "too slow under Miri")]
    fn partial_struct_skips_unknown_inline_payload_over_budget() {
        #[derive(Deserialize)]
        struct PartialRecord {
            known: bool,
        }

        let payload_size = super::MAXIMUM_DATA_STRUCTURE_BYTES + 1;
        for control in [0x5f, 0x9f] {
            let mut payload = large_string(payload_size);
            payload[0] = control; // string or bytes with a three-byte extended size

            let mut buf = vec![0xe2, 0x47]; // two-entry map, seven-byte key
            buf.extend_from_slice(b"unknown");
            buf.extend_from_slice(&payload);
            buf.extend_from_slice(&[0x45]); // five-byte key
            buf.extend_from_slice(b"known");
            buf.extend_from_slice(&[0x01, 0x07]); // true

            let mut decoder = Decoder::new(&buf, 0);
            let decoded = PartialRecord::deserialize(&mut decoder).unwrap();
            assert!(decoded.known);
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "too slow under Miri")]
    fn budgeted_standalone_scalar_entry_points_enforce_payload_limit() {
        // The enum identifier receives the 32-byte allowance, so exceed both
        // that allowance and the ordinary 2 MiB payload budget by one byte.
        let size =
            super::MAXIMUM_DATA_STRUCTURE_BYTES + super::MAXIMUM_UNCHARGED_IDENTIFIER_BYTES + 1;
        let buf = large_string(size);

        let mut decoder = Decoder::new(&buf, 0);
        let err = serde_json::Value::deserialize(&mut decoder).unwrap_err();
        assert!(matches!(*err, MaxMindDbError::ResourceLimit { .. }));

        let mut decoder = Decoder::new(&buf, 0);
        let err = RawValueSeed.deserialize(&mut decoder).unwrap_err();
        assert!(matches!(*err, MaxMindDbError::ResourceLimit { .. }));

        let mut decoder = Decoder::new(&buf, 0);
        let err = StandaloneScalarEnum::deserialize(&mut decoder).unwrap_err();
        assert!(matches!(*err, MaxMindDbError::ResourceLimit { .. }));

        // A directly requested typed scalar intentionally retains its
        // unbudgeted fast path because one scalar cannot amplify through
        // container or pointer fan-out.
        let mut decoder = Decoder::new(&buf, 0);
        let decoded = <&str>::deserialize(&mut decoder).unwrap();
        assert_eq!(decoded.len(), size);
    }

    #[test]
    #[cfg_attr(miri, ignore = "too slow under Miri")]
    fn standalone_scalar_retains_unbudgeted_fast_path() {
        let size = super::MAXIMUM_DATA_STRUCTURE_BYTES + 1;
        let buf = large_string(size);

        let mut decoder = Decoder::new(&buf, 0);
        let decoded = <&str>::deserialize(&mut decoder).unwrap();
        assert_eq!(decoded.len(), size);
    }

    fn repeated_4k_payload_array(control: u8, element_count: usize) -> (Vec<u8>, usize) {
        // A shared 4 KiB string or bytes value followed by an array of pointers
        // to it. Both payload types use the same extended-size representation.
        assert!(matches!(control, 0x5e | 0x9e));
        let mut buf = vec![control, 0x0e, 0xe3]; // size: 285 + 3,811 = 4,096
        buf.resize(buf.len() + 4096, b'a');
        let array_offset = buf.len();

        assert!((285..=u16::MAX as usize + 285).contains(&element_count));
        buf.extend_from_slice(&[0x1e, 0x04]); // array with a two-byte extended size
        buf.extend_from_slice(&((element_count - 285) as u16).to_be_bytes());
        for _ in 0..element_count {
            append_pointer(&mut buf, 0);
        }

        (buf, array_offset)
    }

    fn pointer_key_map(entry_count: usize) -> (Vec<u8>, usize) {
        // A shared 4 KiB string followed by a map whose keys all point to it.
        let mut buf = vec![0x5e, 0x0e, 0xe3]; // string size: 285 + 3,811 = 4,096
        buf.resize(buf.len() + 4096, b'k');
        let map_offset = buf.len();

        assert!((285..=u16::MAX as usize + 285).contains(&entry_count));
        buf.push(0xfe); // map with a two-byte extended size
        buf.extend_from_slice(&((entry_count - 285) as u16).to_be_bytes());
        for _ in 0..entry_count {
            append_pointer(&mut buf, 0);
            buf.extend_from_slice(&[0x00, 0x07]); // false
        }

        (buf, map_offset)
    }

    fn repeated_inline_key_map_array(element_count: usize) -> (Vec<u8>, usize) {
        // A one-entry map with a 4 KiB inline key, followed by an array of
        // pointers that repeatedly expands that map.
        let mut buf = vec![0xe1, 0x5e, 0x0e, 0xe3]; // map(1), string(4,096)
        buf.resize(buf.len() + 4096, b'k');
        buf.extend_from_slice(&[0x00, 0x07]); // false
        let array_offset = buf.len();

        assert!((285..=u16::MAX as usize + 285).contains(&element_count));
        buf.extend_from_slice(&[0x1e, 0x04]); // array with a two-byte extended size
        buf.extend_from_slice(&((element_count - 285) as u16).to_be_bytes());
        for _ in 0..element_count {
            append_pointer(&mut buf, 0);
        }

        (buf, array_offset)
    }

    #[test]
    fn dynamic_map_keys_are_charged_once() {
        // 512 copies of a 4 KiB key exactly fill the 2 MiB payload budget.
        // Dynamic maps precharge keys before invoking an identifier visitor;
        // the visitor must not charge the same payload a second time.
        let (buf, map_offset) = pointer_key_map(512);
        let mut decoder = Decoder::new(&buf, map_offset);
        let value = RawValueSeed.deserialize(&mut decoder).unwrap();

        let RawValue::Map(entries) = value else {
            panic!("expected map");
        };
        assert_eq!(entries.len(), 512);

        // Raw identifiers have a small uncharged allowance. The full dynamic
        // precharge must still reject the first key beyond the payload budget.
        let (buf, map_offset) = pointer_key_map(513);
        let mut decoder = Decoder::new(&buf, map_offset);
        let err = RawValueSeed.deserialize(&mut decoder).unwrap_err();
        assert!(matches!(*err, MaxMindDbError::ResourceLimit { .. }));
        assert!(err
            .to_string()
            .contains("maximum size of data structure string and bytes"));
    }

    fn compare_cached_key<'de, K>(
        buf: &'de [u8],
        start: usize,
        limit: usize,
        remaining: u32,
        seed: K,
    ) where
        K: DeserializeSeed<'de> + Copy,
        K::Value: fmt::Debug + PartialEq,
    {
        let mut cached = Decoder::new_with_limit(buf, start, limit);
        let mut original = Decoder::new_with_limit(buf, start, limit);
        for decoder in [&mut cached, &mut original] {
            decoder.activate_budget();
            decoder.payload_remaining = remaining;
        }

        let actual = super::MapAccessor::<true> {
            de: &mut cached,
            count: 2,
        }
        .next_key_seed(seed)
        .map_err(|error| format!("{error:?}"));
        // Reference the previous map-key algorithm: precharge, decode from the
        // original cursor, then retain whichever payload charge is larger.
        let expected = (|| {
            let (charged, _) = original.count_payload_at_current()?;
            let after = original.payload_remaining;
            original.payload_remaining = remaining;
            let result = seed.deserialize(&mut original).map(Some);
            if charged {
                original.payload_remaining = original.payload_remaining.min(after);
            }
            result
        })()
        .map_err(|error: super::DecoderError| format!("{error:?}"));

        assert_eq!(
            actual, expected,
            "start={start}, limit={limit}, remaining={remaining}"
        );
        assert_eq!(cached.current_ptr, original.current_ptr);
        assert_eq!(cached.state, original.state);
        assert_eq!(cached.payload_remaining, original.payload_remaining);
    }

    #[test]
    #[cfg_attr(miri, ignore = "too slow under Miri")]
    fn cached_map_keys_preserve_values_errors_cursors_and_budgets() {
        let mut buf = [0x61; 80];
        buf[..2].copy_from_slice(&[0x20, 10]);
        for control in 0..=255 {
            buf[10] = control;
            for limit in 0..=buf.len() {
                for remaining in [0, 1, 28, 32, 4096] {
                    compare_cached_key(&buf, 0, limit, remaining, RawIdentifierSeed);
                    compare_cached_key(&buf, 10, limit, remaining, RawIdentifierSeed);
                }
            }
        }
        for &(pointer, target) in &[
            (&[0x20, 8][..], 8),
            (&[0x28, 0, 0][..], 2048),
            (&[0x30, 0, 0, 0][..], 526_336),
            (&[0x38, 0, 0, 0, 8][..], 8),
        ] {
            let mut buf = pointer.to_vec();
            buf.resize(target, 0);
            buf.extend([0x5e, 0, 0]); // 285-byte string
            buf.resize(buf.len() + 285, 0xff); // identifiers preserve raw UTF-8 bytes
            for limit in [pointer.len() - 1, target, buf.len() - 1, buf.len()] {
                for remaining in [0, 284, 285, 4096] {
                    compare_cached_key(&buf, 0, limit, remaining, RawIdentifierSeed);
                }
            }
        }
    }

    #[test]
    fn cached_map_keys_preserve_other_serde_entry_points() {
        use std::marker::PhantomData;

        let cases: &[&[u8]] = &[
            &[0x41, b'x'],
            &[0x20, 4, 0xa1, 42, 0x41, b'x'],
            &[0x20, 4, 0xa1, 42, 0x41],
            &[0x81, 0xff], // bytes are not string identifiers
            &[0xa1, 42],
            &[0xe0],
        ];
        for &buf in cases {
            for remaining in [0, 1, 4096] {
                compare_cached_key(buf, 0, buf.len(), remaining, PhantomData::<String>);
                compare_cached_key(
                    buf,
                    0,
                    buf.len(),
                    remaining,
                    PhantomData::<serde_json::Value>,
                );
                compare_cached_key(
                    buf,
                    0,
                    buf.len(),
                    remaining,
                    PhantomData::<serde::de::IgnoredAny>,
                );
            }
        }
    }

    #[test]
    #[cfg(not(feature = "unsafe-str-decode"))]
    fn cached_map_keys_do_not_bypass_utf8_validation_for_strings() {
        use std::marker::PhantomData;

        for buf in [&[0x41, 0xff][..], &[0x20, 2, 0x41, 0xff][..]] {
            compare_cached_key(buf, 0, buf.len(), 4096, PhantomData::<String>);
            compare_cached_key(buf, 0, buf.len(), 4096, PhantomData::<serde_json::Value>);
            compare_cached_key(buf, 0, buf.len(), 4096, RawIdentifierSeed);
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "too slow under Miri")]
    fn dynamic_any_map_keys_are_charged_once() {
        // deserialize_any activates the budget itself. The map accessor's
        // precharge must still suppress exactly one payload charge rather than
        // charging each 4 KiB key twice.
        let (buf, map_offset) = pointer_key_map(512);
        let mut decoder = Decoder::new(&buf, map_offset);
        assert_eq!(
            decoder.deserialize_any(AnyKeyMapVisitor).unwrap(),
            AnyKeyMap(512)
        );

        // The precharge remains effective: one additional key exceeds 2 MiB.
        let (buf, map_offset) = pointer_key_map(513);
        let mut decoder = Decoder::new(&buf, map_offset);
        let err = decoder.deserialize_any(AnyKeyMapVisitor).unwrap_err();
        assert!(matches!(*err, MaxMindDbError::ResourceLimit { .. }));
        assert!(err
            .to_string()
            .contains("maximum size of data structure string and bytes"));
    }

    #[test]
    fn navigation_charges_repeated_pointer_keys() {
        let (buf, map_offset) = pointer_key_map(513);
        let mut decoder = Decoder::new(&buf, map_offset);
        let (size, type_num) = decoder.consume_container_header().unwrap();
        assert_eq!((size, type_num), (513, super::TYPE_MAP));

        for _ in 0..512 {
            assert_eq!(decoder.read_str_as_bytes().unwrap().len(), 4096);
            decoder.skip_value().unwrap();
        }
        let err = decoder.read_str_as_bytes().unwrap_err();

        assert!(err
            .to_string()
            .contains("maximum size of data structure string and bytes"));
    }

    #[test]
    #[cfg_attr(miri, ignore = "too slow under Miri")]
    fn flattened_pointer_keys_cannot_bypass_payload_budget() {
        #[derive(Debug, Deserialize)]
        struct Flattened {
            #[serde(flatten)]
            fields: std::collections::HashMap<String, serde::de::IgnoredAny>,
        }

        // Each key charges 4,096 - 32 = 4,064 bytes after the per-identifier
        // allowance. 516 copies leave 128 bytes in the 2 MiB payload budget.
        let (buf, map_offset) = pointer_key_map(516);
        let mut decoder = Decoder::new(&buf, map_offset);
        let decoded = Flattened::deserialize(&mut decoder).unwrap();
        assert_eq!(decoded.fields.len(), 1);

        // The 517th copy exceeds that budget. Serde buffers flattened keys, so
        // concrete struct identifier decoding must charge long keys while
        // ordinary short City keys stay on the uncharged fast path.
        let (buf, map_offset) = pointer_key_map(517);
        let mut decoder = Decoder::new(&buf, map_offset);
        let err = Flattened::deserialize(&mut decoder).unwrap_err();

        assert!(matches!(*err, MaxMindDbError::ResourceLimit { .. }));
        assert!(err
            .to_string()
            .contains("maximum size of data structure string and bytes"));
    }

    #[test]
    #[cfg_attr(miri, ignore = "too slow under Miri")]
    fn repeated_maps_with_inline_keys_cannot_bypass_payload_budget() {
        #[derive(Debug, Deserialize)]
        struct Flattened {
            #[serde(flatten)]
            fields: std::collections::HashMap<String, serde::de::IgnoredAny>,
        }

        // The inline path has the same exact boundary as pointer-backed keys.
        let (buf, array_offset) = repeated_inline_key_map_array(516);
        let mut decoder = Decoder::new(&buf, array_offset);
        let decoded = Vec::<Flattened>::deserialize(&mut decoder).unwrap();
        assert_eq!(decoded.len(), 516);
        assert!(decoded.iter().all(|value| value.fields.len() == 1));

        // One additional expansion exceeds the aggregate identifier budget.
        let (buf, array_offset) = repeated_inline_key_map_array(517);
        let mut decoder = Decoder::new(&buf, array_offset);
        let err = Vec::<Flattened>::deserialize(&mut decoder).unwrap_err();

        assert!(matches!(*err, MaxMindDbError::ResourceLimit { .. }));
        assert!(err
            .to_string()
            .contains("maximum size of data structure string and bytes"));
    }

    #[allow(dead_code)]
    #[derive(Debug, Deserialize)]
    enum RecursiveEnum {
        Next(Box<RecursiveEnum>),
        End,
    }

    fn recursive_enum_chain(in_array: bool) -> (Vec<u8>, usize) {
        let mut buf = vec![0x44, b'N', b'e', b'x', b't'];
        let start = buf.len();
        if in_array {
            buf.extend_from_slice(&[0x01, 0x04]); // one-element array
        }
        for _ in 0..=super::MAXIMUM_DATA_STRUCTURE_DEPTH {
            append_pointer(&mut buf, 0);
        }
        buf.extend_from_slice(&[0x43, b'E', b'n', b'd']);
        (buf, start)
    }

    #[test]
    fn recursive_newtype_enum_is_depth_bounded() {
        run_on_bounded_stack(|| {
            let (buf, start) = recursive_enum_chain(false);
            let mut decoder = Decoder::new(&buf, start);
            let err = RecursiveEnum::deserialize(&mut decoder).unwrap_err();

            assert!(err
                .to_string()
                .contains("exceeded maximum data structure depth"));
        });
    }

    #[test]
    fn recursive_newtype_enum_inside_array_is_depth_bounded() {
        run_on_bounded_stack(|| {
            let (buf, start) = recursive_enum_chain(true);
            let mut decoder = Decoder::new(&buf, start);
            let err = Vec::<RecursiveEnum>::deserialize(&mut decoder).unwrap_err();

            assert!(err
                .to_string()
                .contains("exceeded maximum data structure depth"));
        });
    }

    #[derive(Debug, Deserialize)]
    struct NestedHashMap(#[allow(dead_code)] std::collections::HashMap<String, NestedHashMap>);
    #[derive(Debug, Deserialize)]
    struct NestedArray(#[allow(dead_code)] Vec<NestedArray>);

    #[derive(Debug, Deserialize)]
    struct NestedMap {
        #[allow(dead_code)]
        a: Option<Box<NestedMap>>,
    }

    /// `depth` nested arrays, each holding the next. The innermost is empty.
    fn nested_arrays(depth: usize) -> Vec<u8> {
        let mut buf = [0x01, 0x04].repeat(depth - 1); // one-element array
        buf.extend_from_slice(&[0x00, 0x04]); // empty array
        buf
    }

    /// `depth` nested maps, each holding the next under the key "a". The
    /// innermost map is `innermost`.
    fn nested_maps(depth: usize, innermost: &[u8]) -> Vec<u8> {
        let mut buf = [0xe1, 0x41, b'a'].repeat(depth - 1);
        buf.extend_from_slice(innermost);
        buf
    }

    /// Pointer and array pairs, each adding two levels. The innermost array
    /// holds `innermost` as its one element, or nothing.
    fn nested_pointer_arrays(pairs: usize, innermost: Option<&[u8]>) -> Vec<u8> {
        let mut buf = Vec::new();
        for pair in 0..pairs {
            let target = pair * 4 + 2;
            // One-byte pointer offsets stop at 2047.
            assert!(target < 2048);
            buf.extend_from_slice(&[0x20 | (target >> 8) as u8, target as u8]);
            if pair + 1 < pairs || innermost.is_some() {
                buf.extend_from_slice(&[0x01, 0x04]);
            } else {
                buf.extend_from_slice(&[0x00, 0x04]);
            }
        }
        buf.extend_from_slice(innermost.unwrap_or_default());
        buf
    }

    /// Spawned threads, including test threads, default to 2 MiB stacks, and
    /// builds with debug assertions check against that. Setting it here keeps
    /// the check independent of RUST_MIN_STACK. Builds without debug
    /// assertions force the decoder's inlining, and an unoptimized one needs
    /// about 3 MiB, so they get 4 MiB.
    fn run_on_bounded_stack(f: impl FnOnce() + Send + 'static) {
        let mib = if cfg!(debug_assertions) { 2 } else { 4 };
        std::thread::Builder::new()
            .stack_size(mib * 1024 * 1024)
            .spawn(f)
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn maximum_depth_fits_bounded_stack() {
        run_on_bounded_stack(|| {
            let depth = usize::from(super::MAXIMUM_DATA_STRUCTURE_DEPTH);
            let arrays = nested_arrays(depth);
            let maps = nested_maps(depth, &[0xe0]);
            // Ignored values have their own, lower skip limit. Put the deepest
            // skip below the deepest typed map.
            let mut ignored = vec![0xe1, 0x41, b'x'];
            ignored.extend(nested_arrays(usize::from(
                super::MAXIMUM_SKIPPED_DATA_STRUCTURE_DEPTH,
            )));
            let maps_with_ignored = nested_maps(depth, &ignored);
            let pointers = nested_pointer_arrays(depth / 2, None);

            for buf in [&arrays, &maps, &pointers] {
                serde_json::Value::deserialize(&mut Decoder::new(buf, 0)).unwrap();
                RawValue::deserialize(&mut Decoder::new(buf, 0)).unwrap();
            }
            NestedArray::deserialize(&mut Decoder::new(&arrays, 0)).unwrap();
            NestedArray::deserialize(&mut Decoder::new(&pointers, 0)).unwrap();
            NestedMap::deserialize(&mut Decoder::new(&maps, 0)).unwrap();
            NestedMap::deserialize(&mut Decoder::new(&maps_with_ignored, 0)).unwrap();
            NestedHashMap::deserialize(&mut Decoder::new(&maps, 0)).unwrap();
        });
    }

    #[test]
    fn depth_limit_applies_before_the_stack_runs_out() {
        run_on_bounded_stack(|| {
            let depth = usize::from(super::MAXIMUM_DATA_STRUCTURE_DEPTH) + 1;
            let arrays = nested_arrays(depth);
            let maps = nested_maps(depth, &[0xe0]);
            // One level past the skip limit, under the deepest allowed map.
            let mut ignored = vec![0xe1, 0x41, b'x'];
            ignored.extend(nested_arrays(
                usize::from(super::MAXIMUM_SKIPPED_DATA_STRUCTURE_DEPTH) + 1,
            ));
            let maps_with_ignored = nested_maps(depth - 1, &ignored);
            // 256 pairs plus one empty array: 513 levels.
            let pointers = nested_pointer_arrays(depth / 2, Some(&[0x00, 0x04]));
            let errors = [
                serde_json::Value::deserialize(&mut Decoder::new(&pointers, 0)).unwrap_err(),
                RawValue::deserialize(&mut Decoder::new(&pointers, 0)).unwrap_err(),
                NestedArray::deserialize(&mut Decoder::new(&pointers, 0)).unwrap_err(),
                serde_json::Value::deserialize(&mut Decoder::new(&arrays, 0)).unwrap_err(),
                serde_json::Value::deserialize(&mut Decoder::new(&maps, 0)).unwrap_err(),
                RawValue::deserialize(&mut Decoder::new(&arrays, 0)).unwrap_err(),
                RawValue::deserialize(&mut Decoder::new(&maps, 0)).unwrap_err(),
                NestedArray::deserialize(&mut Decoder::new(&arrays, 0)).unwrap_err(),
                NestedMap::deserialize(&mut Decoder::new(&maps, 0)).unwrap_err(),
                NestedMap::deserialize(&mut Decoder::new(&maps_with_ignored, 0)).unwrap_err(),
                NestedHashMap::deserialize(&mut Decoder::new(&maps, 0)).unwrap_err(),
            ];
            for error in errors {
                assert!(
                    error
                        .to_string()
                        .contains("exceeded maximum data structure depth"),
                    "unexpected error: {error}"
                );
                assert!(matches!(*error, MaxMindDbError::InvalidDatabase { .. }));
            }
        });
    }

    #[test]
    fn verification_bounds_overlapping_string_scans() {
        // Each header is also valid ASCII inside preceding string payloads.
        // Distinct target offsets defeat the exact-target cache.
        let size = 65_821 + 65_536;
        let mut buf = [0x5f, 0x01, 0x00, 0x00].repeat(64);
        buf.resize(buf.len() + size, b'a');
        let mut state = VerificationState::new(buf.len());
        let allowance = state.work_remaining;
        for index in 0..8 {
            Decoder::new(&buf, index * 4)
                .skip_value_for_verification(&mut state)
                .unwrap();
        }
        assert_eq!(state.work_remaining, allowance - 8 * (size + 1));

        let mut decoder = Decoder::new(&buf, 8 * 4);
        let err = decoder.skip_value_for_verification(&mut state).unwrap_err();
        assert!(matches!(
            *err,
            MaxMindDbError::ResourceLimit {
                offset: Some(36),
                ..
            }
        ));
        // The rejected string was neither scanned nor cached; only its visit
        // was charged, and its cursor still points to the start of the payload.
        assert_eq!(state.work_remaining, allowance - 8 * (size + 1) - 1);
        assert_eq!(decoder.offset(), 36);
        assert_eq!(state.validated.len(), 8);
        assert!(state.active.is_empty());
    }

    #[test]
    fn verification_bounds_repeated_inline_traversal_across_roots() {
        let mut buf = [0x01, 0x04].repeat(64); // nested one-element arrays
        buf.extend_from_slice(&[0x00, 0x07]); // false
        let mut state = VerificationState::new(buf.len());
        // Successive roots start inside earlier arrays. Inline children aren't
        // cached, so even without string scans their repeated visits need a cap.
        let err = (0..64)
            .try_for_each(|index| {
                Decoder::new(&buf, index * 2).skip_value_for_verification(&mut state)
            })
            .unwrap_err();
        assert!(matches!(*err, MaxMindDbError::ResourceLimit { .. }));
        assert_eq!(state.work_remaining, 0);
        assert!(state.active.is_empty());
    }

    #[test]
    #[cfg_attr(miri, ignore = "too slow under Miri")]
    fn verification_allows_large_nonoverlapping_payloads() {
        let size = super::MAXIMUM_DATA_STRUCTURE_BYTES + 1;
        let mut buf = vec![0x5f];
        buf.extend_from_slice(&((size - 65_821) as u32).to_be_bytes()[1..]);
        buf.resize(buf.len() + size, b'a');
        let mut state = VerificationState::new(buf.len());
        Decoder::new(&buf, 0)
            .skip_value_for_verification(&mut state)
            .unwrap();
    }

    #[test]
    fn verification_work_allowance_does_not_overflow() {
        let mut state = VerificationState::new(usize::MAX);
        assert_eq!(state.work_remaining, usize::MAX);
        state.charge(usize::MAX, 0).unwrap();
        assert!(matches!(
            state.charge(1, 0).map_err(|error| *error),
            Err(MaxMindDbError::ResourceLimit { .. })
        ));
        assert_eq!(state.work_remaining, 0);
    }

    #[test]
    fn test_verification_rejects_invalid_bool_size() {
        // Extended bool type with an invalid size value of two.
        let mut decoder = Decoder::new(&[0x02, 0x07], 0);
        let err = decoder
            .skip_value_for_verification(&mut VerificationState::new(decoder.limit))
            .unwrap_err();

        assert!(matches!(*err, MaxMindDbError::InvalidDatabase { .. }));
    }

    #[test]
    fn test_verification_rejects_and_does_not_cache_invalid_utf8() {
        let buf = [0x41, 0xff];
        let mut state = VerificationState::new(buf.len());

        for _ in 0..2 {
            let mut decoder = Decoder::new(&buf, 0);
            let err = decoder.skip_value_for_verification(&mut state).unwrap_err();

            assert!(matches!(*err, MaxMindDbError::InvalidDatabase { .. }));
            assert!(err.to_string().contains("invalid UTF-8"));
            assert!(state.validated.is_empty());
            assert!(state.active.is_empty());
        }

        #[cfg(not(feature = "unsafe-str-decode"))]
        {
            let mut decoder = Decoder::new(&buf, 0);
            let err = String::deserialize(&mut decoder).unwrap_err();
            assert!(err.to_string().contains("invalid UTF-8"));
        }
    }

    fn append_pointer(buf: &mut Vec<u8>, target: usize) {
        assert!(target < 2048);
        buf.push(0x20 | ((target >> 8) as u8));
        buf.push(target as u8);
    }

    #[test]
    fn test_verification_caches_shared_pointer_targets() {
        // A false boolean leaf followed by arrays containing two pointers to
        // the preceding value. Without caching, verification work doubles at
        // every level even though the encoded graph grows only linearly.
        let mut buf = vec![0x00, 0x07];
        let mut target = 0;
        const LEVELS: usize = 20;

        for _ in 0..LEVELS {
            let array = buf.len();
            buf.extend_from_slice(&[0x02, 0x04]);
            append_pointer(&mut buf, target);
            append_pointer(&mut buf, target);
            target = array;
        }

        let mut decoder = Decoder::new(&buf, target);
        let mut state = VerificationState::new(buf.len());
        decoder.skip_value_for_verification(&mut state).unwrap();

        assert_eq!(state.validated.len(), LEVELS + 1);
        assert!(state.active.is_empty());
    }

    #[test]
    fn test_verification_rejects_data_pointer_cycles() {
        // Two single-element arrays whose values point to each other.
        let mut buf = vec![0x01, 0x04];
        append_pointer(&mut buf, 4);
        buf.extend_from_slice(&[0x01, 0x04]);
        append_pointer(&mut buf, 0);

        let mut decoder = Decoder::new(&buf, 0);
        let err = decoder
            .skip_value_for_verification(&mut VerificationState::new(decoder.limit))
            .unwrap_err();

        assert!(matches!(*err, MaxMindDbError::InvalidDatabase { .. }));
        assert!(err.to_string().contains("cyclic data pointer"));
    }

    fn uint16(value: u16) -> Vec<u8> {
        let mut encoded = vec![0xa2];
        encoded.extend_from_slice(&value.to_be_bytes());
        encoded
    }

    fn uint32(value: u32) -> Vec<u8> {
        let mut encoded = vec![0xc4];
        encoded.extend_from_slice(&value.to_be_bytes());
        encoded
    }

    fn uint64(value: u64) -> Vec<u8> {
        let mut encoded = vec![0x08, 0x02];
        encoded.extend_from_slice(&value.to_be_bytes());
        encoded
    }

    fn uint128(value: u128) -> Vec<u8> {
        let mut encoded = vec![0x10, 0x03];
        encoded.extend_from_slice(&value.to_be_bytes());
        encoded
    }

    fn int32(value: i32) -> Vec<u8> {
        let mut encoded = vec![0x04, 0x01];
        encoded.extend_from_slice(&value.to_be_bytes());
        encoded
    }

    fn float(value: f32) -> Vec<u8> {
        let mut encoded = vec![0x04, 0x08];
        encoded.extend_from_slice(&value.to_be_bytes());
        encoded
    }

    fn double(value: f64) -> Vec<u8> {
        let mut encoded = vec![0x68];
        encoded.extend_from_slice(&value.to_be_bytes());
        encoded
    }

    /// Decodes `encoded` inline and through a pointer, checking that the
    /// cursor ends after the inline value and after the pointer.
    fn decode_inline_and_pointer<T>(encoded: &[u8]) -> [Result<T, String>; 2]
    where
        T: serde::de::DeserializeOwned,
    {
        let mut decoder = Decoder::new(encoded, 0);
        let inline = T::deserialize(&mut decoder).map_err(|error| error.to_string());
        if inline.is_ok() {
            assert_eq!(decoder.offset(), encoded.len());
        }

        let mut pointer = vec![0x20, 0x02];
        pointer.extend_from_slice(encoded);
        let mut decoder = Decoder::new(&pointer, 0);
        let via_pointer = T::deserialize(&mut decoder).map_err(|error| error.to_string());
        assert_eq!(decoder.offset(), 2, "pointer continuation not restored");
        assert_eq!(decoder.state & super::DEPTH_MASK, 0, "depth not restored");

        [inline, via_pointer]
    }

    #[allow(clippy::float_cmp)]
    #[test]
    fn typed_scalars_widen_lossless_narrower_types() {
        for result in decode_inline_and_pointer::<u32>(&uint16(0xfffe)) {
            assert_eq!(result.unwrap(), 0xfffe);
        }

        for (encoded, expected) in [
            (uint16(0xfffe), 0xfffe_u64),
            (uint32(0xffff_fffe), 0xffff_fffe),
        ] {
            for result in decode_inline_and_pointer::<u64>(&encoded) {
                assert_eq!(result.unwrap(), expected);
            }
        }

        for (encoded, expected) in [
            (uint16(0xfffe), 0xfffe_u128),
            (uint32(0xffff_fffe), 0xffff_fffe),
            (uint64(u64::MAX - 1), u128::from(u64::MAX - 1)),
        ] {
            for result in decode_inline_and_pointer::<u128>(&encoded) {
                assert_eq!(result.unwrap(), expected);
            }
        }

        for result in decode_inline_and_pointer::<i32>(&uint16(0xfffe)) {
            assert_eq!(result.unwrap(), 0xfffe);
        }

        // Serde routes these through the same entry points.
        for result in decode_inline_and_pointer::<usize>(&uint32(7)) {
            assert_eq!(result.unwrap(), 7);
        }
        for result in decode_inline_and_pointer::<std::num::NonZeroU64>(&uint16(7)) {
            assert_eq!(result.unwrap().get(), 7);
        }
        for result in decode_inline_and_pointer::<isize>(&uint32(7)) {
            assert_eq!(result.unwrap(), 7);
        }

        for value in [1.1_f32, f32::MAX, f32::INFINITY, -0.0] {
            for result in decode_inline_and_pointer::<f64>(&float(value)) {
                let decoded = result.unwrap();
                assert_eq!(decoded, f64::from(value));
                assert_eq!(decoded.is_sign_negative(), value.is_sign_negative());
            }
        }
        for result in decode_inline_and_pointer::<f64>(&float(f32::NAN)) {
            assert!(result.unwrap().is_nan());
        }

        // Exact types still decode through the direct path.
        for result in decode_inline_and_pointer::<u64>(&uint64(u64::MAX)) {
            assert_eq!(result.unwrap(), u64::MAX);
        }
        for result in decode_inline_and_pointer::<f64>(&double(42.5)) {
            assert_eq!(result.unwrap(), 42.5);
        }
    }

    /// A visitor that relies on Serde's default methods, which pass every
    /// unsigned integer narrower than 128 bits to `visit_u64`.
    struct DefaultsToU64;

    impl<'de> Visitor<'de> for DefaultsToU64 {
        type Value = u64;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("u64")
        }

        fn visit_u64<E>(self, value: u64) -> Result<u64, E> {
            Ok(value)
        }
    }

    type CheckFn = fn(&[u8]) -> [Result<(), String>; 2];

    /// Decodes `encoded` as `T` inline and through a pointer, keeping only
    /// whether each succeeded.
    fn decode_unit<T: serde::de::DeserializeOwned>(encoded: &[u8]) -> [Result<(), String>; 2] {
        decode_inline_and_pointer::<T>(encoded).map(|result| result.map(|_| ()))
    }

    #[test]
    fn narrower_integer_types_get_fitting_uint128_values_as_u64() {
        fn decode<T: serde::de::DeserializeOwned>(value: u128) -> Result<T, String> {
            let encoded = uint128(value);
            let mut decoder = Decoder::new(&encoded, 0);
            T::deserialize(&mut decoder).map_err(|err| err.to_string())
        }

        assert_eq!(decode::<u8>(255).unwrap(), 255);
        assert_eq!(decode::<i8>(42).unwrap(), 42);
        assert_eq!(decode::<i16>(42).unwrap(), 42);
        assert_eq!(decode::<i64>(i64::MAX as u128).unwrap(), i64::MAX);
        assert_eq!(decode::<i128>(u128::from(u64::MAX) + 1).unwrap(), 1 << 64);

        let err = decode::<u8>(256).unwrap_err();
        assert!(
            err.contains("invalid value: integer `256`, expected u8"),
            "{err}"
        );
        let err = decode::<i64>(u128::from(u64::MAX) + 1).unwrap_err();
        assert!(err.contains("as u128"), "{err}");

        // `deserialize_i64` still passes each stored integer to the method
        // for its stored type, so a visitor that relies on Serde's default
        // methods sees a `u64`, including for a uint128 that fits.
        for encoded in [uint16(7), uint32(7), uint64(7), uint128(7)] {
            let mut decoder = Decoder::new(&encoded, 0);
            assert_eq!(decoder.deserialize_i64(DefaultsToU64).unwrap(), 7);
        }
    }

    #[test]
    fn integer_types_accept_any_mmdb_integer_that_fits() {
        fn ok<T>(encoded: &[u8], expected: T)
        where
            T: serde::de::DeserializeOwned + PartialEq + fmt::Debug,
        {
            for result in decode_inline_and_pointer::<T>(encoded) {
                assert_eq!(result.unwrap(), expected);
            }
        }

        // Wider stored types decode when the value fits, up to the edge of
        // the field's range.
        ok(&uint32(u16::MAX.into()), u16::MAX);
        ok(&uint64(5), 5_u16);
        ok(&uint128(5), 5_u16);
        ok(&int32(5), 5_u16);
        ok(&uint64(u32::MAX.into()), u32::MAX);
        ok(&uint128(7), 7_u32);
        ok(&int32(i32::MAX), i32::MAX as u32);
        ok(&uint128(u64::MAX.into()), u64::MAX);
        ok(&int32(3), 3_u64);
        ok(&int32(0), 0_u128);
        ok(&uint32(i32::MAX as u32), i32::MAX);
        ok(&uint64(9), 9_i32);
        ok(&uint128(9), 9_i32);

        // Types without an MMDB type of their own follow the same rule.
        ok(&uint128(255), 255_u8);
        ok(&int32(-128), -128_i8);
        ok(&uint64(32_767), 32_767_i16);
        ok(&uint64(42), 42_i64);
        ok(&uint128(i64::MAX as u128), i64::MAX);
        ok(&uint128(42), 42_i128);
        ok(&int32(-2), -2_i128);

        // Serde routes these through the same entry points.
        ok(&uint128(7), 7_usize);
        ok(&uint128(7), 7_isize);
        ok(&uint32(7), std::num::NonZeroU16::new(7).unwrap());
    }

    #[test]
    fn integer_values_that_do_not_fit_return_decoding_errors() {
        let cases: [(Vec<u8>, CheckFn, &str); 13] = [
            (
                uint32(u32::from(u16::MAX) + 1),
                decode_unit::<u16>,
                "invalid value: integer `65536`, expected u16",
            ),
            (
                uint64(u64::from(u32::MAX) + 1),
                decode_unit::<u32>,
                "invalid value: integer `4294967296`, expected u32",
            ),
            (
                uint128(u128::from(u64::MAX) + 1),
                decode_unit::<u64>,
                "integer `18446744073709551616` as u128, expected u64",
            ),
            (int32(-1), decode_unit::<u64>, "integer `-1`, expected u64"),
            (
                int32(-1),
                decode_unit::<u128>,
                "integer `-1`, expected u128",
            ),
            (
                uint32(i32::MAX as u32 + 1),
                decode_unit::<i32>,
                "integer `2147483648`, expected i32",
            ),
            (uint16(256), decode_unit::<u8>, "integer `256`, expected u8"),
            (
                int32(-129),
                decode_unit::<i8>,
                "integer `-129`, expected i8",
            ),
            (
                uint64(32_768),
                decode_unit::<i16>,
                "integer `32768`, expected i16",
            ),
            (
                uint128(i64::MAX as u128 + 1),
                decode_unit::<i64>,
                "invalid value: integer `9223372036854775808`, expected i64",
            ),
            (
                uint128(u128::from(u64::MAX) + 1),
                decode_unit::<i64>,
                "integer `18446744073709551616` as u128, expected i64",
            ),
            (
                uint64(u64::MAX),
                decode_unit::<i64>,
                "integer `18446744073709551615`, expected i64",
            ),
            (
                uint32(0),
                decode_unit::<std::num::NonZeroU16>,
                "expected a nonzero u16",
            ),
        ];

        for (encoded, decode, expected) in cases {
            for result in decode(&encoded) {
                let err = result.unwrap_err();
                assert!(err.contains(expected), "{err:?} lacks {expected:?}");
            }
        }

        // A uint128 that fits in a `u64` gets the same range check.
        for result in decode_unit::<u16>(&uint128(70_000)) {
            let err = result.unwrap_err();
            assert!(
                err.contains("invalid value: integer `70000`, expected u16"),
                "{err:?}"
            );
        }

        // `Saturating` clamps instead, for any stored value up to u64::MAX.
        use std::num::Saturating;
        for encoded in [uint32(70_000), uint64(70_000), uint128(70_000)] {
            for result in decode_inline_and_pointer::<Saturating<u16>>(&encoded) {
                assert_eq!(result.unwrap(), Saturating(u16::MAX));
            }
        }
        for result in decode_inline_and_pointer::<Saturating<u64>>(&int32(-5)) {
            assert_eq!(result.unwrap(), Saturating(0));
        }
        for result in
            decode_inline_and_pointer::<Saturating<u64>>(&uint128(u128::from(u64::MAX) + 1))
        {
            assert!(result.unwrap_err().contains("as u128"));
        }

        // The error is a decoding error, not a database error.
        let encoded = uint16(256);
        let mut decoder = Decoder::new(&encoded, 0);
        let err = u8::deserialize(&mut decoder).unwrap_err();
        assert!(
            matches!(*err, MaxMindDbError::Decoding { .. }),
            "unexpected error: {err}"
        );

        // A stored type that converts on the cold path keeps the offset a
        // type mismatch there would report: the payload's, also behind a
        // pointer.
        let encoded = uint64(u64::from(u32::MAX) + 1);
        let mut pointer = vec![0x20, 0x02];
        pointer.extend_from_slice(&encoded);
        for (buf, offset) in [(&encoded, 2), (&pointer, 4)] {
            let mut decoder = Decoder::new(buf, 0);
            let err = u32::deserialize(&mut decoder).unwrap_err();
            assert!(
                matches!(*err, MaxMindDbError::Decoding { offset: Some(o), .. } if o == offset),
                "unexpected error: {err:?}"
            );
        }
    }

    #[test]
    fn buffered_integers_convert_through_serde_visitors() {
        // Serde buffers flattened fields, so they see the stored type, and
        // Serde's integer visitors check its range.
        #[derive(serde::Deserialize)]
        struct Inner {
            v: u16,
        }
        #[derive(serde::Deserialize)]
        struct Outer {
            #[serde(flatten)]
            inner: Inner,
        }

        let mut encoded = vec![0xe1, 0x41, b'v'];
        encoded.extend(uint32(5));
        let mut decoder = Decoder::new(&encoded, 0);
        assert_eq!(Outer::deserialize(&mut decoder).unwrap().inner.v, 5);

        let mut encoded = vec![0xe1, 0x41, b'v'];
        encoded.extend(uint32(70_000));
        let mut decoder = Decoder::new(&encoded, 0);
        let err = Outer::deserialize(&mut decoder).err().unwrap();
        assert!(
            err.to_string().contains("integer `70000`, expected u16"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn typed_scalars_reject_non_numeric_and_lossy_types() {
        let cases: [(Vec<u8>, CheckFn, &str); 7] = [
            (
                double(1.0),
                decode_unit::<f32>,
                "expected float, got type 3",
            ),
            (uint32(1), decode_unit::<f64>, "expected double, got type 6"),
            (uint16(1), decode_unit::<bool>, "expected bool, got type 5"),
            (double(1.0), decode_unit::<u64>, "expected u64, got type 3"),
            (float(1.0), decode_unit::<i32>, "expected i32, got type 15"),
            (
                vec![0x41, b'1'],
                decode_unit::<u16>,
                "expected u16, got type 2",
            ),
            (
                double(1.0),
                decode_unit::<i64>,
                "invalid type: floating point",
            ),
        ];

        for (encoded, decode, expected) in cases {
            for result in decode(&encoded) {
                let err = result.unwrap_err();
                assert!(err.contains(expected), "{err:?} lacks {expected:?}");
            }
        }
    }

    #[test]
    fn exact_scalar_decoder_does_not_widen() {
        fn check<T: serde::de::DeserializeOwned + fmt::Debug>(encoded: &[u8], expected: &str) {
            let mut pointer = vec![0x20, 0x02];
            pointer.extend_from_slice(encoded);
            for buf in [encoded, &pointer] {
                let mut decoder = Decoder::new_exact_scalars(buf, 0);
                let err = T::deserialize(&mut decoder).unwrap_err();
                assert!(
                    matches!(*err, MaxMindDbError::Decoding { .. }),
                    "unexpected error: {err}"
                );
                assert!(err.to_string().contains(expected), "{err} lacks {expected}");
                assert_eq!(decoder.state & super::DEPTH_MASK, 0, "depth not restored");
            }
        }

        check::<u32>(&uint16(1), "expected u32, got type 5");
        check::<u64>(&uint16(1), "expected u64, got type 5");
        check::<u64>(&uint32(1), "expected u64, got type 6");
        check::<u128>(&uint16(1), "expected u128, got type 5");
        check::<u128>(&uint32(1), "expected u128, got type 6");
        check::<u128>(&uint64(1), "expected u128, got type 9");
        check::<i32>(&uint16(1), "expected i32, got type 5");
        check::<f64>(&float(1.0), "expected double, got type 15");
        check::<u16>(&uint32(1), "expected u16, got type 6");
        check::<u32>(&uint64(1), "expected u32, got type 9");
        check::<u64>(&uint128(1), "expected u64, got type 10");
        check::<i32>(&uint32(1), "expected i32, got type 6");

        // Types without an MMDB type of their own still convert.
        let mut decoder = Decoder::new_exact_scalars(&[0xc4, 0, 0, 0, 7], 0);
        assert_eq!(u8::deserialize(&mut decoder).unwrap(), 7);

        // The exact type still decodes.
        let mut decoder = Decoder::new_exact_scalars(&[0xc4, 0, 0, 0, 7], 0);
        assert_eq!(u32::deserialize(&mut decoder).unwrap(), 7);
    }

    #[test]
    fn widened_float_errors_report_the_value_offset() {
        struct RejectsF64;

        impl<'de> Visitor<'de> for RejectsF64 {
            type Value = f64;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a small f64")
            }

            fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<f64, E> {
                Err(E::custom("too big"))
            }
        }

        // The offset is the payload's, also behind a pointer.
        let encoded = float(1.0);
        let mut pointer = vec![0x20, 0x02];
        pointer.extend_from_slice(&encoded);
        for (buf, offset) in [(&encoded, 2), (&pointer, 4)] {
            let mut decoder = Decoder::new(buf, 0);
            let err = decoder.deserialize_f64(RejectsF64).unwrap_err();
            assert!(
                matches!(*err, MaxMindDbError::Decoding { offset: Some(o), .. } if o == offset),
                "unexpected error: {err:?}"
            );
        }
    }

    #[test]
    fn integer_conversion_calls_the_requested_visit_method() {
        struct OnlyU64;

        impl<'de> Visitor<'de> for OnlyU64 {
            type Value = u64;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("u64")
            }

            fn visit_u64<E>(self, value: u64) -> Result<u64, E> {
                Ok(value)
            }

            fn visit_u16<E: serde::de::Error>(self, _: u16) -> Result<u64, E> {
                Err(E::custom("visit_u16 called"))
            }

            fn visit_u32<E: serde::de::Error>(self, _: u32) -> Result<u64, E> {
                Err(E::custom("visit_u32 called"))
            }
        }

        for encoded in [uint16(7), uint32(7), uint128(7), int32(7)] {
            let mut decoder = Decoder::new(&encoded, 0);
            assert_eq!(decoder.deserialize_u64(OnlyU64).unwrap(), 7);
        }

        // A value that does not fit goes to the method for its stored type.
        let encoded = uint128(u128::MAX);
        let mut decoder = Decoder::new(&encoded, 0);
        let err = decoder.deserialize_u64(OnlyU64).unwrap_err();
        assert!(
            err.to_string().contains("as u128"),
            "unexpected error: {err}"
        );

        // Types without an MMDB type of their own still pass a stored
        // integer to the method for its stored type.
        let encoded = uint32(7);
        let mut decoder = Decoder::new(&encoded, 0);
        let err = decoder.deserialize_i64(OnlyU64).unwrap_err();
        assert!(
            err.to_string().contains("visit_u32 called"),
            "unexpected error: {err}"
        );
    }

    type DecodeFn = fn(&mut Decoder<'_>) -> Result<(), super::DecoderError>;

    #[test]
    fn typed_scalar_conversion_rejects_truncated_values() {
        let cases: [(&[u8], DecodeFn, &str); 6] = [
            (&[0xa2, 0x01], |de| u64::deserialize(de).map(|_| ()), "u16"),
            (
                &[0xc4, 0x01, 0x02],
                |de| u128::deserialize(de).map(|_| ()),
                "u32",
            ),
            (
                &[0x04, 0x08, 0x00],
                |de| f64::deserialize(de).map(|_| ()),
                "float",
            ),
            (
                &[0x08, 0x02, 0x01],
                |de| u32::deserialize(de).map(|_| ()),
                "u64",
            ),
            (
                &[0x04, 0x01, 0x00],
                |de| u16::deserialize(de).map(|_| ()),
                "i32",
            ),
            // A pointer to a pointer is rejected before any widening.
            (
                &[0x20, 0x00],
                |de| u64::deserialize(de).map(|_| ()),
                "pointer",
            ),
        ];
        for (encoded, decode, expected) in cases {
            let mut inline = Decoder::new(encoded, 0);
            let mut pointer = vec![0x20, 0x02];
            pointer.extend_from_slice(encoded);
            let mut via_pointer = Decoder::new(&pointer, 0);

            for decoder in [&mut inline, &mut via_pointer] {
                let err = decode(decoder).unwrap_err();
                assert!(
                    matches!(*err, MaxMindDbError::InvalidDatabase { .. }),
                    "unexpected error: {err}"
                );
                assert!(err.to_string().contains(expected), "{err} lacks {expected}");
            }
            assert_eq!(via_pointer.offset(), 2, "pointer continuation not restored");
            assert_eq!(
                via_pointer.state & super::DEPTH_MASK,
                0,
                "depth not restored"
            );
        }
    }
}
