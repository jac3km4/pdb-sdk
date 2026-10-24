//! Errors from stream I/O, binary codecs, and unsupported PDB features.

use thiserror::Error;

/// A library result, defaulting to [`enum@Error`].
pub type Result<A, E = Error> = std::result::Result<A, E>;

/// A failure while reading or writing PDB data.
///
/// Malformed data can surface as either an I/O error or a codec error, depending
/// on which layer detects it; variants are not a complete validity classification.
#[derive(Debug, Error)]
pub enum Error {
    /// Underlying I/O failure or an I/O-layer data-validation error.
    #[error("I/O error: {0}")]
    IoFailed(#[from] std::io::Error),
    /// Binary encoding or decoding failure.
    #[error("encoding error: {0}")]
    EncodingFailed(#[from] declio::Error),
    /// A recognized format feature or version is not supported.
    #[error("unsupported feature: {0}")]
    UnsupportedFeature(&'static str),
    /// A required stream name, index, or debug-stream slot was not found.
    #[error("stream not found: {0}")]
    StreamNotFound(&'static str),
    /// A padding byte did not match the expected CodeView padding pattern.
    #[error("invalid padding: {0}")]
    InvalidPadding(u8),
}
