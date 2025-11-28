//! Database metadata types.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Metadata about the MaxMind DB file.
#[derive(Deserialize, Serialize, Clone, Debug)]
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
