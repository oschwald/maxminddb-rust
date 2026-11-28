//! Shared-target caching and work accounting for database verification.
//!
//! Keeping these cold helpers separate and out of line limits verification
//! bookkeeping's influence on the record decoder's generated code.

use super::DecodeResult;
use crate::MaxMindDbError;
use std::collections::{HashMap, HashSet};

/// Tracks data values visited by a single database verification pass.
#[derive(Debug)]
pub(crate) struct VerificationState {
    /// Offsets of roots and pointer targets that verified successfully,
    /// mapped to their skip-depth height so a later reference from a deeper
    /// position can still enforce the depth limit without re-traversal.
    /// Offsets are stored as `u32` (see [`Self::key`]) to keep entries at
    /// eight bytes, since this map can hold one entry per data record. A
    /// pointer offset is never cached, because a pointer is valid as a root
    /// but not as a pointer target, and a cache hit skips the pointer-chain
    /// check.
    pub(super) validated: HashMap<u32, u16>,
    pub(super) active: HashSet<usize>,
    /// Deepest skip depth reached by the root or pointer target being
    /// verified. Tracking it here, instead of returning heights through the
    /// recursion, keeps the traversal's return type as small as the decoder's.
    pub(super) deepest: u16,
    pub(super) work_remaining: usize,
}

impl VerificationState {
    #[cold]
    #[inline(never)]
    pub(crate) fn new(section_size: usize) -> Self {
        Self {
            validated: HashMap::new(),
            active: HashSet::new(),
            deepest: 0,
            // Allow ordinary inline and pointer-target visits with headroom,
            // but bound repeated traversal and scans of overlapping payloads.
            // Saturation keeps the allowance bounded even on 32-bit targets.
            work_remaining: section_size.saturating_mul(8),
        }
    }

    /// Reserves cache space for `roots` data records, which are all cached
    /// except those that are pointers, so a large database does not rehash
    /// the cache repeatedly as it grows.
    pub(crate) fn reserve_roots(&mut self, roots: usize) {
        self.validated.reserve(roots);
    }

    /// Returns the cache key for a data section offset. Roots come from
    /// search tree records and pointer targets from pointers, both at most
    /// 32 bits, so a larger offset means the database is corrupt.
    #[inline]
    pub(super) fn key(offset: usize) -> DecodeResult<u32> {
        u32::try_from(offset).map_err(|_| Self::offset_too_large(offset))
    }

    #[cold]
    #[inline(never)]
    fn offset_too_large(offset: usize) -> super::DecoderError {
        MaxMindDbError::invalid_database_at("data offset does not fit in 32 bits", offset).into()
    }

    #[cold]
    #[inline(never)]
    pub(super) fn charge(&mut self, amount: usize, offset: usize) -> DecodeResult<()> {
        self.work_remaining = self.work_remaining.checked_sub(amount).ok_or_else(|| {
            MaxMindDbError::resource_limit_at("exceeded maximum verification work", offset)
        })?;
        Ok(())
    }
}
