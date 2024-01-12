use thiserror::Error;

#[derive(Debug, Error)]
pub enum Crypt4GHError {
    #[error("Unable to parse `{0}` from bytes")]
    FromBytesError(String),
    #[error("Invalid value for spec: `{0}`")]
    InvalidSpec(String),
}