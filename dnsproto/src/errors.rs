use std::net::AddrParseError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum DNSProtoErr {
    #[error("packet parse failed")]
    PacketParseError,
    #[error("packet serial failed")]
    PacketSerializeError,

    #[error(transparent)]
    ParseZoneDataErr(#[from] ParseZoneDataErr),

    #[error("read zone file: `{path:?}` error: {err:?}")]
    IOError { path: String, err: String },

    #[error("unimplemented error")]
    UnImplementedError,
}

#[derive(Error, Debug, PartialEq)]
pub enum ParseZoneDataErr {
    #[error("domain: `{0}` validate fail")]
    ValidDomainErr(String),

    #[error("dns label: `{0}` validate fail")]
    ValidDomainLabelErr(String),

    #[error("dns type: `{0}` validate fail")]
    ValidTypeErr(String),

    #[error("dns ttl: `{0}` validate fail")]
    ValidTTLErr(String),

    #[error("dns origin: `{0}` validate fail")]
    ValidOriginErr(String),
    #[error("default domain ttl is not set")]
    NoDefaultTTL,
    #[error("default domain name is not set")]
    NoDefaultDomain,
    #[error("default domain type is not set")]
    NoDomainType,
    #[error("default origin domain is not set")]
    NoOriginDomain,
    #[error("general fail: `{0}`")]
    GeneralFail(String),

    #[error(transparent)]
    AddrParseError(#[from] AddrParseError),
    #[error("empty zone data error")]
    EmptyStrErr,
}
