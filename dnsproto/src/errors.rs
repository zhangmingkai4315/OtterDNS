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

    #[error("packet encode error")]
    EncodeError,

    #[error("read zone file: `{path:?}` error: {err:?}")]
    IOError { path: String, err: String },

    #[error("unimplemented error")]
    UnImplementedError,
}

impl From<std::io::Error> for DNSProtoErr {
    fn from(_: std::io::Error) -> Self {
        DNSProtoErr::PacketParseError
    }
}

impl From<std::net::AddrParseError> for DNSProtoErr {
    fn from(_: AddrParseError) -> Self {
        DNSProtoErr::PacketParseError
    }
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
    NoDefaultTTLErr,
    #[error("default domain name is not set")]
    NoDefaultDomainErr,
    #[error("default domain type is not set")]
    NoDomainTypeErr,
    #[error("default origin domain is not set")]
    NoOriginDomainErr,
    #[error("general fail: `{0}`")]
    GeneralErr(String),

    #[error(transparent)]
    AddrParseError(#[from] AddrParseError),
    #[error("empty zone data error")]
    EmptyStrErr,

    #[error("unimplemented")]
    UnimplementedErr,
}
