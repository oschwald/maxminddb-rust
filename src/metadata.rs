//! Database metadata types.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::MaxMindDbError;

/// Metadata about the MaxMind DB file.
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct Metadata {
    /// Major version of the binary format (always 2).
    pub binary_format_major_version: u16,
    /// Minor version of the binary format (always 0).
    pub binary_format_minor_version: u16,
    /// Unix timestamp when the database was built.
    pub build_epoch: u64,
    /// Database type (e.g., "GeoIP2-City", "GeoLite2-Country").
    pub database_type: String,
    /// Map of language codes to database descriptions.
    pub description: BTreeMap<String, String>,
    /// IP version supported (4 or 6).
    pub ip_version: u16,
    /// Languages available in the database.
    pub languages: Vec<String>,
    /// Number of nodes in the search tree.
    pub node_count: u32,
    /// Size of each record in bits (24, 28, or 32).
    pub record_size: u16,
}

impl Metadata {
    /// Returns the database build time as a `SystemTime`.
    ///
    /// This converts the `build_epoch` Unix timestamp to a `SystemTime`.
    /// If `build_epoch` is too large to represent on this platform, this
    /// returns an [`InvalidDatabase`](MaxMindDbError::InvalidDatabase) error.
    ///
    /// # Example
    ///
    /// ```
    /// use maxminddb::Reader;
    ///
    /// let reader = Reader::open_readfile("test-data/test-data/GeoIP2-City-Test.mmdb").unwrap();
    /// let build_time = reader.metadata().build_time().unwrap();
    /// println!("Database built: {:?}", build_time);
    /// ```
    #[inline]
    pub fn build_time(&self) -> Result<SystemTime, MaxMindDbError> {
        UNIX_EPOCH
            .checked_add(Duration::from_secs(self.build_epoch))
            .ok_or_else(|| {
                MaxMindDbError::invalid_database(format!(
                    "build_epoch - Unix timestamp is too large to represent as SystemTime: {}",
                    self.build_epoch
                ))
            })
    }
}
