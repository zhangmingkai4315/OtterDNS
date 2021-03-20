use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum StorageError {
    #[error("domain not exist in storage: {0}")]
    DomainNotFoundError(String),

    #[error("storage not ready")]
    StorageNotReadyError,
}
