use std::net::AddrParseError;
use std::num::ParseIntError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum SettingError {
    #[error("parse config file failed: {0}")]
    ParseConfigError(String),
    #[error("validation config setting failed: {0}")]
    ValidationError(String),

    #[error("validation server setting failed: {0}")]
    ValidationServerConfigError(String),
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
    // original parse zone data error
    #[error("domain: `{0}` validate fail")]
    ValidDomainErr(String),
    #[error("not a valid query message")]
    ValidQueryDomainErr,
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

    #[error("edns version number not support")]
    BadEDNSVersion,
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

    #[error("parse data fail: dns packet with empty question section")]
    ParseEmptyQuestionError,

    #[error("packet parse failed")]
    PacketParseError,
    #[error("packet serial failed")]
    PacketSerializeError,
    #[error("packet encode error")]
    EncodeError,

    #[error("txt encode overflow error")]
    EncodeTxtLengthTooLongError,

    #[error("read zone file: `{path:?}` error: {err:?}")]
    IOError { path: String, err: String },

    #[error("fail: `{0}`")]
    GeneralErr(String),

    #[error("unimplemented error: {0}")]
    UnImplementedError(String),
}

impl From<std::io::Error> for DNSProtoErr {
    fn from(_: std::io::Error) -> Self {
        DNSProtoErr::PacketParseError
    }
}

impl From<config::ConfigError> for SettingError {
    fn from(err: config::ConfigError) -> Self {
        SettingError::ValidationServerConfigError(err.to_string())
    }
}

impl<I: std::fmt::Debug> From<nom::Err<(I, nom::error::ErrorKind)>> for DNSProtoErr {
    fn from(err_nom: nom::Err<(I, nom::error::ErrorKind)>) -> Self {
        match err_nom {
            nom::Err::Error(err) | nom::Err::Failure(err) => {
                DNSProtoErr::ParseDNSFromStrWithTypeError(
                    format!("{:?}", err.0),
                    format!("{:?}", err.1),
                )
            }
            nom::Err::Incomplete(needed) => {
                DNSProtoErr::ParseDNSFromStrIncompleteError(format!("{:?}", needed))
            }
        }
    }
}

impl From<ParseIntError> for DNSProtoErr {
    fn from(error: ParseIntError) -> Self {
        DNSProtoErr::ParseDNSFromStrError(error.to_string())
    }
}
// impl From<DNSProtoErr> for StorageError {
//     fn from(err: DNSProtoErr) -> Self {
//         StorageError::ValidFQDNError(err.to_string())
//     }
// }

#[derive(Error, Debug)]
pub enum OtterError {
    #[error(transparent)]
    DNSProtoError(#[from] DNSProtoErr),
    #[error(transparent)]
    SettingError(#[from] SettingError),

    #[error(transparent)]
    NetworkError(#[from] NetworkError),

    #[error(transparent)]
    StorageError(#[from] StorageError),
}

#[derive(Error, Debug)]
pub enum NetworkError {
    #[error(transparent)]
    AddrParseError(AddrParseError),

    #[error("{0}")]
    IOError(String),
}

impl From<AddrParseError> for NetworkError {
    fn from(err: AddrParseError) -> Self {
        NetworkError::AddrParseError(err)
    }
}
impl From<std::io::Error> for NetworkError {
    fn from(err: std::io::Error) -> Self {
        NetworkError::IOError(err.to_string())
    }
}
