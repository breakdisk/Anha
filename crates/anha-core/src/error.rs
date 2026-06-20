//! Shared error type for the core crate.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid handle: {0}")]
    InvalidHandle(String),

    #[error("invalid record: {0}")]
    InvalidRecord(String),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}
