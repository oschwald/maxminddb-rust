//! Shared-target caching and work accounting for database verification.
//!
//! Keeping these cold helpers separate and out of line limits verification
//! bookkeeping's influence on the record decoder's generated code.

use super::DecodeResult;
use crate::MaxMindDbError;
use std::collections::HashSet;

/// Tracks data values visited by a single database verification pass.
#[derive(Debug)]
pub(crate) struct VerificationState {
    pub(super) validated: HashSet<usize>,
    pub(super) active: HashSet<usize>,
    pub(super) work_remaining: usize,
}

impl VerificationState {
    #[cold]
    #[inline(never)]
    pub(crate) fn new(section_size: usize) -> Self {
        Self {
            validated: HashSet::new(),
            active: HashSet::new(),
            // Allow ordinary inline and pointer-target visits with headroom,
            // but bound repeated traversal and scans of overlapping payloads.
            // Saturation keeps the allowance bounded even on 32-bit targets.
            work_remaining: section_size.saturating_mul(8),
        }
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
