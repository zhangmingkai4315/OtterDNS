use std::net::AddrParseError;
use std::num::ParseIntError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum SettingError {
    #[error("parse config file failed: {0}")]
    ParseConfigError(String),
    #[error("validation config setting failed: {0}")]
    ValidationError(String),
}

#[derive(Error, PartialEq, Debug)]
pub enum StorageError {
    #[error("domain not exist in storage")]
    DomainNotFoundError(String),

    #[error("domain :{0} exist but query type:{1} not exist")]
    DNSTypeNotFoundError(String, String),
    #[error("storage not ready")]
    StorageNotReadyError,
    #[error("soa resource record not found")]
    SOAResourceError,
    #[error("can't add CNAME RR to a node that already has RRs present")]
    AddCNAMEConflictError,

    #[error("can't add non-NSEC RR to a node that already has a CNAME")]
    AddOtherRRConflictCNAME,

    #[error("domain :{0} not belong to zone : {0}")]
    ZoneOutOfArea(String, String),
    #[error("{0}")]
    ValidFQDNError(String),
    #[error("unimplemented feature")]
    Unimplemented,
}

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

    #[error("unimplemented error: {0}")]
    UnImplementedError(String),
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

    #[error("fail: `{0}`")]
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

    #[error("unimplemented: {0}")]
    UnimplementedErr(String),
}
impl From<String> for ParseZoneDataErr {
    fn from(err_str: String) -> Self {
        ParseZoneDataErr::GeneralErr(err_str)
    }
}
impl<I: std::fmt::Debug> From<nom::Err<(I, nom::error::ErrorKind)>> for ParseZoneDataErr {
    fn from(err_nom: nom::Err<(I, nom::error::ErrorKind)>) -> Self {
        match err_nom {
            nom::Err::Error(err) | nom::Err::Failure(err) => {
                ParseZoneDataErr::ParseDNSFromStrWithTypeError(
                    format!("{:?}", err.0),
                    format!("{:?}", err.1),
                )
            }
            nom::Err::Incomplete(needed) => {
                ParseZoneDataErr::ParseDNSFromStrIncompleteError(format!("{:?}", needed))
            }
        }
    }
}
// impl From<ParseZoneDataErr> for nom::Err<nom::error::Error<&[u8]>>{
//     fn from(err: ParseZoneDataErr) -> Self {
//         nom::Err::Error(nom::error::Error::new())
//     }
// }
impl From<ParseIntError> for ParseZoneDataErr {
    fn from(error: ParseIntError) -> Self {
        ParseZoneDataErr::ParseDNSFromStrError(error.to_string())
    }
}
impl From<ParseZoneDataErr> for StorageError {
    fn from(err: ParseZoneDataErr) -> Self {
        StorageError::ValidFQDNError(err.to_string())
    }
}

#[derive(Error, Debug, PartialEq)]
pub enum OtterError {
    #[error(transparent)]
    DNSProtoError(#[from] DNSProtoErr),

    #[error(transparent)]
    StorageError(#[from] StorageError),
}
