use nom;
use std::net::AddrParseError;
use std::num::ParseIntError;
use thiserror::Error;
// use std::str::FromStr;

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

    #[error("domain is not a valid fqdn: `{0}`")]
    ValidFQDNError(String),

    #[error("general fail: `{0}`")]
    GeneralErr(String),

    #[error(transparent)]
    AddrParseError(#[from] AddrParseError),
    #[error("empty zone data error")]
    EmptyStrErr,

    #[error("parse dns from str error: `{0}`")]
    ParseDNSFromStrError(String),
    #[error("parse dns from str error: `{0}` / `{1}`")]
    ParseDNSFromStrWithTypeError(String, String),
    #[error("parse dns from str incomplete error: `{0}`")]
    ParseDNSFromStrIncompleteError(String),

    #[error("unimplemented")]
    UnimplementedErr,
}

impl<I: std::fmt::Debug> From<nom::Err<(I, nom::error::ErrorKind)>> for ParseZoneDataErr {
    fn from(i: nom::Err<(I, nom::error::ErrorKind)>) -> Self {
        match i {
            nom::Err::Error(err) | nom::Err::Failure(err) => {
                ParseZoneDataErr::ParseDNSFromStrWithTypeError(
                    format!("{:?}", err.0),
                    format!("{:?}", err.1),
                )
            }
            nom::Err::Incomplete(i) => {
                ParseZoneDataErr::ParseDNSFromStrIncompleteError(format!("{:?}", i))
            }
        }
    }
}

impl From<ParseIntError> for ParseZoneDataErr {
    fn from(error: ParseIntError) -> Self {
        ParseZoneDataErr::ParseDNSFromStrError(error.to_string())
    }
}
