use thiserror::Error;

pub type Result<A, E = Error> = std::result::Result<A, E>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    IoFailed(#[from] std::io::Error),
    #[error("encoding error: {0}")]
    EncodingFailed(#[from] declio::Error),
    #[error("unsupported feature: {0}")]
    UnsupportedFeature(&'static str),
    #[error("stream not found: {0}")]
    StreamNotFound(&'static str),
    #[error("invalid padding: {0}")]
    InvalidPadding(u8),
}
