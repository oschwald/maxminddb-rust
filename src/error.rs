//! Error types for MaxMind DB operations.

use std::fmt::Display;
use std::io;

use ipnetwork::IpNetworkError;
use serde::de;
use thiserror::Error;

/// Error returned by MaxMind DB operations.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum MaxMindDbError {
    /// The database file is invalid or corrupted.
    #[error("{}", format_invalid_database(.message, .offset))]
    InvalidDatabase {
        /// Description of what is invalid.
        message: String,
        /// Byte offset in the database where the error was detected.
        offset: Option<usize>,
    },

    /// An I/O error occurred while reading the database.
    #[error("i/o error: {0}")]
    Io(
        #[from]
        #[source]
        io::Error,
    ),

    /// Memory mapping failed.
    #[cfg(feature = "mmap")]
    #[error("memory map error: {0}")]
    Mmap(#[source] io::Error),

    /// Error decoding data from the database.
    #[error("{}", format_decoding_error(.message, .offset, .path.as_deref()))]
    Decoding {
        /// Description of the decoding error.
        message: String,
        /// Byte offset in the data section where the error occurred.
        offset: Option<usize>,
        /// JSON-pointer-like path to the field (e.g., "/city/names/en").
        path: Option<String>,
    },

    /// The provided network/CIDR is invalid.
    #[error("invalid network: {0}")]
    InvalidNetwork(
        #[from]
        #[source]
        IpNetworkError,
    ),

    /// The provided input is invalid for this operation.
    #[error("invalid input: {message}")]
    InvalidInput {
        /// Description of what is invalid about the input.
        message: String,
    },
}

fn format_invalid_database(message: &str, offset: &Option<usize>) -> String {
    match offset {
        Some(off) => format!("invalid database at offset {off}: {message}"),
        None => format!("invalid database: {message}"),
    }
}

fn format_decoding_error(message: &str, offset: &Option<usize>, path: Option<&str>) -> String {
    match (offset, path) {
        (Some(off), Some(p)) => format!("decoding error at offset {off} (path: {p}): {message}"),
        (Some(off), None) => format!("decoding error at offset {off}: {message}"),
        (None, Some(p)) => format!("decoding error (path: {p}): {message}"),
        (None, None) => format!("decoding error: {message}"),
    }
}

impl MaxMindDbError {
    /// Creates an InvalidDatabase error with just a message.
    pub fn invalid_database(message: impl Into<String>) -> Self {
        MaxMindDbError::InvalidDatabase {
            message: message.into(),
            offset: None,
        }
    }

    /// Creates an InvalidDatabase error with message and offset.
    pub fn invalid_database_at(message: impl Into<String>, offset: usize) -> Self {
        MaxMindDbError::InvalidDatabase {
            message: message.into(),
            offset: Some(offset),
        }
    }

    /// Creates a Decoding error with just a message.
    pub fn decoding(message: impl Into<String>) -> Self {
        MaxMindDbError::Decoding {
            message: message.into(),
            offset: None,
            path: None,
        }
    }

    /// Creates a Decoding error with message and offset.
    pub fn decoding_at(message: impl Into<String>, offset: usize) -> Self {
        MaxMindDbError::Decoding {
            message: message.into(),
            offset: Some(offset),
            path: None,
        }
    }

    /// Creates a Decoding error with message, offset, and path.
    pub fn decoding_at_path(
        message: impl Into<String>,
        offset: usize,
        path: impl Into<String>,
    ) -> Self {
        MaxMindDbError::Decoding {
            message: message.into(),
            offset: Some(offset),
            path: Some(path.into()),
        }
    }

    /// Creates an InvalidInput error.
    pub fn invalid_input(message: impl Into<String>) -> Self {
        MaxMindDbError::InvalidInput {
            message: message.into(),
        }
    }
}

impl de::Error for MaxMindDbError {
    fn custom<T: Display>(msg: T) -> Self {
        MaxMindDbError::decoding(msg.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};

    #[test]
    fn test_error_display() {
        // Error without offset
        assert_eq!(
            format!(
                "{}",
                MaxMindDbError::invalid_database("something went wrong")
            ),
            "invalid database: something went wrong".to_owned(),
        );
        // Error with offset
        assert_eq!(
            format!(
                "{}",
                MaxMindDbError::invalid_database_at("something went wrong", 42)
            ),
            "invalid database at offset 42: something went wrong".to_owned(),
        );
        let io_err = Error::new(ErrorKind::NotFound, "file not found");
        assert_eq!(
            format!("{}", MaxMindDbError::from(io_err)),
            "i/o error: file not found".to_owned(),
        );

        #[cfg(feature = "mmap")]
        {
            let mmap_io_err = Error::new(ErrorKind::PermissionDenied, "mmap failed");
            assert_eq!(
                format!("{}", MaxMindDbError::Mmap(mmap_io_err)),
                "memory map error: mmap failed".to_owned(),
            );
        }

        // Decoding error without offset
        assert_eq!(
            format!("{}", MaxMindDbError::decoding("unexpected type")),
            "decoding error: unexpected type".to_owned(),
        );
        // Decoding error with offset
        assert_eq!(
            format!("{}", MaxMindDbError::decoding_at("unexpected type", 100)),
            "decoding error at offset 100: unexpected type".to_owned(),
        );
        // Decoding error with offset and path
        assert_eq!(
            format!(
                "{}",
                MaxMindDbError::decoding_at_path("unexpected type", 100, "/city/names/en")
            ),
            "decoding error at offset 100 (path: /city/names/en): unexpected type".to_owned(),
        );

        let net_err = IpNetworkError::InvalidPrefix;
        assert_eq!(
            format!("{}", MaxMindDbError::from(net_err)),
            "invalid network: invalid prefix".to_owned(),
        );

        // InvalidInput error
        assert_eq!(
            format!("{}", MaxMindDbError::invalid_input("bad address")),
            "invalid input: bad address".to_owned(),
        );
    }
}
