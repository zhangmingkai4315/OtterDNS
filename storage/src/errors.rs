#![allow(dead_code)]
use dnsproto::errors::ParseZoneDataErr;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum StorageError {
    #[error("domain not exist in storage: {0}")]
    DomainNotFoundError(String),

    #[error("storage not ready")]
    StorageNotReadyError,

    #[error("can't add CNAME RR to a node that already has RRs present")]
    AddCNAMEConflictError,

    #[error("can't add non-NSEC RR to a node that already has a CNAME")]
    AddOtherRRConflictCNAME,
    #[error("{0}")]
    ValidFQDNError(String),
}

impl From<ParseZoneDataErr> for StorageError {
    fn from(err: ParseZoneDataErr) -> Self {
        StorageError::ValidFQDNError(err.to_string())
    }
}
