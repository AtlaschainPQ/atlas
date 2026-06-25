use thiserror::Error;

#[derive(Error, Debug)]
pub enum CoreError {
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Invalid data: {0}")]
    InvalidData(String),
    #[error("Crypto error: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),
}
