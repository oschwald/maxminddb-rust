//! Binary format decoder for MaxMind DB files.
//!
//! This module implements deserialization of the MaxMind DB binary format
//! into Rust types via serde. The decoder handles all MaxMind DB data types
//! including pointers, maps, arrays, and primitive types.
//!
//! Most users should not need to interact with this module directly.
//! Use [`Reader::lookup()`](crate::Reader::lookup) for normal lookups.

use log::debug;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::forward_to_deserialize_any;
use std::collections::HashSet;
use std::convert::TryInto;

use crate::error::MaxMindDbError;

// MaxMind DB type constants
const TYPE_EXTENDED: u8 = 0;
pub(crate) const TYPE_POINTER: u8 = 1;
const TYPE_STRING: u8 = 2;
const TYPE_DOUBLE: u8 = 3;
const TYPE_BYTES: u8 = 4;
const TYPE_UINT16: u8 = 5;
const TYPE_UINT32: u8 = 6;
pub(crate) const TYPE_MAP: u8 = 7;
const TYPE_INT32: u8 = 8;
const TYPE_UINT64: u8 = 9;
const TYPE_UINT128: u8 = 10;
pub(crate) const TYPE_ARRAY: u8 = 11;
const TYPE_BOOL: u8 = 14;
const TYPE_FLOAT: u8 = 15;

/// Maximum recursion depth for nested data structures.
/// This matches the value used in libmaxminddb and the Go reader.
const MAXIMUM_DATA_STRUCTURE_DEPTH: u16 = 512;

/// Lower limit for values skipped through unknown fields or IgnoredAny.
/// Skipping is recursive and can be reached by corrupt data that callers did
/// not explicitly request, so keep the limit below small default thread stacks.
const MAXIMUM_SKIPPED_DATA_STRUCTURE_DEPTH: u16 = 128;

#[inline(always)]
fn to_usize(base: u8, bytes: &[u8]) -> usize {
    bytes
        .iter()
        .fold(base as usize, |acc, &b| (acc << 8) | b as usize)
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

/// Decoder for MaxMind DB binary format.
///
/// Implements serde's `Deserializer` trait. Handles pointer resolution,
/// type coercion, and nested data structures.
#[derive(Debug)]
pub(crate) struct Decoder<'de> {
    buf: &'de [u8],
    limit: usize,
    current_ptr: usize,
    depth: u16,
}

/// Tracks data values visited by a single database verification pass.
#[derive(Debug, Default)]
pub(crate) struct VerificationState {
    validated: HashSet<usize>,
    active: HashSet<usize>,
}

impl<'de> Decoder<'de> {
    pub(crate) fn new(buf: &'de [u8], start_ptr: usize) -> Decoder<'de> {
        Decoder::new_with_limit(buf, start_ptr, buf.len())
    }

    pub(crate) fn new_with_limit(buf: &'de [u8], start_ptr: usize, limit: usize) -> Decoder<'de> {
        debug_assert!(limit <= buf.len());
        Decoder {
            buf,
            limit,
            current_ptr: start_ptr,
            depth: 0,
        }
    }

    /// Check and increment depth, returning error if limit exceeded.
    #[inline]
    fn enter_nested(&mut self) -> DecodeResult<()> {
        if self.depth >= MAXIMUM_DATA_STRUCTURE_DEPTH {
            return Err(self.invalid_db_error(
                "exceeded maximum data structure depth; database is likely corrupt",
            ));
        }
        self.depth += 1;
        Ok(())
    }

    /// Decrement depth when exiting a nested structure.
    #[inline]
    fn exit_nested(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    /// Create an InvalidDatabase error with current offset context.
    #[inline]
    fn invalid_db_error(&self, msg: &str) -> MaxMindDbError {
        MaxMindDbError::invalid_database_at(msg, self.current_ptr)
    }

    /// Create a Decoding error with current offset context.
    #[inline]
    fn decode_error(&self, msg: &str) -> MaxMindDbError {
        MaxMindDbError::decoding_at(msg, self.current_ptr)
    }

    #[inline(always)]
    fn type_mismatch(&self, label: &str, type_num: u8) -> MaxMindDbError {
        self.decode_error(&format!("expected {label}, got type {type_num}"))
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
        // SAFETY: Decoder constructors ensure `limit <= buf.len()`, and all
        // callers reach this helper only after checking `end <= limit`.
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
        // SAFETY: The check above proves `current_ptr < limit`, and decoder
        // construction guarantees `limit <= buf.len()`.
        let b = unsafe { *self.buf.get_unchecked(self.current_ptr) };
        self.current_ptr += 1;
        Ok(b)
    }

    #[inline(always)]
    fn size_from_ctrl_byte(&mut self, ctrl_byte: u8, type_num: u8) -> DecodeResult<usize> {
        let size = (ctrl_byte & 0x1f) as usize;
        // Extended type - size field is used differently
        if type_num == TYPE_EXTENDED {
            return Ok(size);
        }

        match size {
            s if s < 29 => Ok(s),
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

    #[inline(always)]
    fn size_and_type(&mut self) -> DecodeResult<(usize, u8)> {
        let ctrl_byte = self.eat_byte()?;
        let mut type_num = ctrl_byte >> 5;
        // Extended type: type 0 means read next byte for actual type
        if type_num == TYPE_EXTENDED {
            type_num = self.eat_byte()? + TYPE_MAP; // Extended types start at 7
        }
        let size = self.size_from_ctrl_byte(ctrl_byte, type_num)?;
        Ok((size, type_num))
    }

    fn decode_any<V: Visitor<'de>>(&mut self, visitor: V) -> DecodeResult<V::Value> {
        match self.decode_any_value()? {
            Value::Any { prev_ptr } => {
                // Pointer dereference - track depth
                self.enter_nested()?;
                let res = self.decode_any(visitor);
                self.exit_nested();
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

            de.enter_nested()?;
            let res = visitor.visit_seq(ArrayAccess { de, count: size });
            de.exit_nested();
            res
        })
    }

    #[inline(always)]
    fn decode_any_value(&mut self) -> DecodeResult<Value<'_, 'de>> {
        let (size, type_num) = self.size_and_type()?;

        Ok(match type_num {
            TYPE_POINTER => {
                let new_ptr = self.decode_pointer(size);
                let prev_ptr = self.current_ptr;
                self.current_ptr = new_ptr;

                Value::Any { prev_ptr }
            }
            TYPE_STRING => Value::String(self.decode_string(size)?),
            TYPE_DOUBLE => Value::F64(self.decode_double(size)?),
            TYPE_BYTES => Value::Bytes(self.decode_bytes(size)?),
            TYPE_UINT16 => Value::U16(self.decode_uint16(size)?),
            TYPE_UINT32 => Value::U32(self.decode_uint32(size)?),
            TYPE_MAP => {
                self.enter_nested()?;
                self.decode_map(size)
            }
            TYPE_INT32 => Value::I32(self.decode_int(size)?),
            TYPE_UINT64 => Value::U64(self.decode_uint64(size)?),
            TYPE_UINT128 => Value::U128(self.decode_uint128(size)?),
            TYPE_ARRAY => {
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

    #[inline(always)]
    fn decode_pointer(&mut self, size: usize) -> usize {
        let pointer_value_offset = [0, 0, 2048, 526_336, 0];
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

        let new_offset = self.checked_offset(size, "string")?;
        let bytes = self.slice(self.current_ptr, new_offset);
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
        use std::str::from_utf8_unchecked;

        let new_offset = self.checked_offset(size, "string")?;
        let bytes = self.slice(self.current_ptr, new_offset);
        self.current_ptr = new_offset;
        if bytes.is_ascii() {
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
    pub(crate) fn peek_type(&mut self) -> DecodeResult<(usize, u8)> {
        let saved_ptr = self.current_ptr;
        let result = self.size_and_type_following_pointers()?;
        self.current_ptr = saved_ptr;
        Ok(result)
    }

    /// Consumes a map or array header in one pass, following a pointer if needed.
    pub(crate) fn consume_container_header(&mut self) -> DecodeResult<(usize, u8)> {
        self.size_and_type_following_pointers()
    }

    /// Gets size and type, following any pointers.
    fn size_and_type_following_pointers(&mut self) -> DecodeResult<(usize, u8)> {
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
        type_num: u8,
        expected_type: u8,
        label: &str,
        decode: F,
    ) -> DecodeResult<T>
    where
        F: FnOnce(&mut Self, usize) -> DecodeResult<T>,
    {
        match type_num {
            TYPE_POINTER => {
                let new_ptr = self.decode_pointer(size);
                let saved_ptr = self.current_ptr;
                self.current_ptr = new_ptr;
                self.enter_nested()?;
                let result = (|| {
                    let (size, type_num) = self.size_and_type()?;
                    if type_num == TYPE_POINTER {
                        return Err(self.invalid_db_error("pointer points to another pointer"));
                    }
                    if type_num != expected_type {
                        return Err(self.type_mismatch(label, type_num));
                    }
                    decode(self, size)
                })();
                self.exit_nested();
                self.current_ptr = saved_ptr;
                result
            }
            t if t == expected_type => decode(self, size),
            _ => Err(self.type_mismatch(label, type_num)),
        }
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
    pub(crate) fn read_str_as_bytes(&mut self) -> DecodeResult<&'de [u8]> {
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
                    self.read_string_bytes(size)
                } else {
                    Err(self.invalid_db_error(&format!("expected string, got type {type_num}")))
                };
                self.current_ptr = saved_ptr;
                result
            }
            TYPE_STRING => self.read_string_bytes(size),
            _ => Err(self.invalid_db_error(&format!("expected string, got type {type_num}"))),
        }
    }

    /// Fast-path identifier decoding:
    /// - Returns `Ok(Some(bytes))` and consumes the identifier when it is a string.
    /// - Returns `Ok(None)` and restores `current_ptr` when the next value is not a string.
    /// - Returns `Err` for malformed pointer chains or invalid string lengths.
    fn try_read_identifier_bytes(&mut self) -> DecodeResult<Option<&'de [u8]>> {
        let saved_ptr = self.current_ptr;
        let (size, type_num) = self.size_and_type()?;
        match type_num {
            TYPE_STRING => self.read_string_bytes(size).map(Some),
            TYPE_POINTER => {
                let new_ptr = self.decode_pointer(size);
                let after_pointer = self.current_ptr;
                self.current_ptr = new_ptr;
                let (inner_size, inner_type) = self.size_and_type()?;
                let result = if inner_type == TYPE_POINTER {
                    Err(self.invalid_db_error("pointer points to another pointer"))
                } else if inner_type == TYPE_STRING {
                    self.read_string_bytes(inner_size).map(Some)
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

    /// Skips the current value, following pointers.
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
    fn skip_value_inner(&mut self, size: usize, type_num: u8, skip_depth: u16) -> DecodeResult<()> {
        // Headers and scalar payloads validate every cursor advance. A
        // successful recursive skip therefore already guarantees that the
        // cursor remains within the decoder limit.
        match type_num {
            TYPE_POINTER => {
                let new_ptr = self.decode_pointer(size);
                let saved_ptr = self.current_ptr;
                self.current_ptr = new_ptr;
                let result = match self.check_skip_depth(skip_depth) {
                    Ok(child_depth) => self.skip_value_with_depth(child_depth),
                    Err(err) => Err(err),
                };
                self.current_ptr = saved_ptr;
                result
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
        type_num: u8,
        skip_depth: u16,
        state: &mut VerificationState,
    ) -> DecodeResult<()> {
        match type_num {
            TYPE_STRING => {
                let end = self.checked_offset(size, "string")?;
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

    deserialize_direct_scalar!(deserialize_bool, TYPE_BOOL, "bool", visit_bool, decode_bool);

    deserialize_direct_scalar!(
        deserialize_u16,
        TYPE_UINT16,
        "u16",
        visit_u16,
        decode_uint16
    );

    deserialize_direct_scalar!(
        deserialize_u32,
        TYPE_UINT32,
        "u32",
        visit_u32,
        decode_uint32
    );

    deserialize_direct_scalar!(
        deserialize_u64,
        TYPE_UINT64,
        "u64",
        visit_u64,
        decode_uint64
    );

    deserialize_direct_scalar!(
        deserialize_u128,
        TYPE_UINT128,
        "u128",
        visit_u128,
        decode_uint128
    );

    deserialize_direct_scalar!(deserialize_i32, TYPE_INT32, "i32", visit_i32, decode_int);

    deserialize_direct_scalar!(
        deserialize_f32,
        TYPE_FLOAT,
        "float",
        visit_f32,
        decode_float
    );

    deserialize_direct_scalar!(
        deserialize_f64,
        TYPE_DOUBLE,
        "double",
        visit_f64,
        decode_double
    );

    deserialize_direct_scalar!(
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

    deserialize_direct_scalar!(
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
        let (size, type_num) = self.size_and_type()?;
        self.decode_direct(size, type_num, TYPE_MAP, "map", |de, size| {
            de.enter_nested()?;
            let res = visitor.visit_map(MapAccessor {
                de,
                count: size * 2,
            });
            de.exit_nested();
            res
        })
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
        self.deserialize_map(visitor)
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

    forward_to_deserialize_any! {
        i8 i16 i64 i128 u8 char unit unit_struct newtype_struct
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

struct MapAccessor<'a, 'de: 'a> {
    de: &'a mut Decoder<'de>,
    count: usize,
}

// `MapAccess` is provided to the `Visitor` to give it the ability to iterate
// through entries of the map.
impl<'de> MapAccess<'de> for MapAccessor<'_, 'de> {
    type Error = MaxMindDbError;

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
    type Error = MaxMindDbError;
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
    type Error = MaxMindDbError;

    fn unit_variant(self) -> DecodeResult<()> {
        Ok(())
    }

    fn newtype_variant_seed<T>(self, seed: T) -> DecodeResult<T::Value>
    where
        T: DeserializeSeed<'de>,
    {
        seed.deserialize(&mut *self.de)
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
    use serde::Deserialize;

    use crate::{MaxMindDbError, Reader};

    use super::{Decoder, VerificationState};

    #[test]
    fn test_decoder_accepts_tuple_with_matching_length() {
        #[allow(dead_code)]
        #[derive(Debug, serde::Deserialize)]
        struct TupleRecord {
            array: (u32, u32, u32),
        }

        #[allow(dead_code)]
        #[derive(Debug, serde::Deserialize)]
        struct TupleStructRecord {
            array: TupleStruct,
        }

        #[allow(dead_code)]
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
            .skip_value_for_verification(&mut VerificationState::default())
            .unwrap_err();

        assert!(matches!(err, MaxMindDbError::InvalidDatabase { .. }));
    }

    #[test]
    fn test_decoder_caps_impossible_container_size_hint() {
        // Extended array with 284 declared elements and no element payload.
        let mut decoder = Decoder::new(&[0x1d, 0x04, 0xff], 0);
        let err = Vec::<serde::de::IgnoredAny>::deserialize(&mut decoder).unwrap_err();

        assert!(matches!(err, MaxMindDbError::InvalidDatabase { .. }));
        assert!(err.to_string().contains("unexpected end of buffer"));
    }

    #[test]
    fn test_verification_rejects_invalid_bool_size() {
        // Extended bool type with an invalid size value of two.
        let mut decoder = Decoder::new(&[0x02, 0x07], 0);
        let err = decoder
            .skip_value_for_verification(&mut VerificationState::default())
            .unwrap_err();

        assert!(matches!(err, MaxMindDbError::InvalidDatabase { .. }));
    }

    #[test]
    fn test_verification_rejects_and_does_not_cache_invalid_utf8() {
        let buf = [0x41, 0xff];
        let mut state = VerificationState::default();

        for _ in 0..2 {
            let mut decoder = Decoder::new(&buf, 0);
            let err = decoder.skip_value_for_verification(&mut state).unwrap_err();

            assert!(matches!(err, MaxMindDbError::InvalidDatabase { .. }));
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
        let mut state = VerificationState::default();
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
            .skip_value_for_verification(&mut VerificationState::default())
            .unwrap_err();

        assert!(matches!(err, MaxMindDbError::InvalidDatabase { .. }));
        assert!(err.to_string().contains("cyclic data pointer"));
    }
}
