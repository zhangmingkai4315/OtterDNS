use std::fmt;
use std::fmt::Formatter;
use std::net::AddrParseError;

#[derive(Debug, PartialEq, Clone)]
pub enum PacketProcessErr {
    PacketParseError,
    PacketSerializeError,
    UnImplementedError,
}

#[derive(Debug, PartialEq, Clone)]
pub enum ParseZoneErr {
    FileNotExist(String),
    ReadFileError(String),
    ParseZoneDataError(String),
}

impl fmt::Display for ParseZoneErr {
    fn fmt(&self, format: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            ParseZoneErr::FileNotExist(ref file_path) => {
                write!(format, "file: {} not exist", file_path)
            }
            ParseZoneErr::ReadFileError(ref err) => write!(format, "read file error: {}", err),
            ParseZoneErr::ParseZoneDataError(ref err) => {
                write!(format, "zone parse error: {}", err)
            }
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum ParseRRErr {
    ValidDomainErr(String),
    ValidTypeErr(String),
    ValidOriginErr(String),
    NoDefaultTTL,
    NoDefaultDomain,
    NoDomainType,
    NoOriginDomain,
    ParseTypeErr(String),
    GeneralFail(String),
    EmptyStrErr,
}

impl fmt::Display for ParseRRErr {
    fn fmt(&self, format: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ParseRRErr::ValidDomainErr(domain) => write!(format, "domain: {} is not valid", domain),
            ParseRRErr::ValidOriginErr(domain) => {
                write!(format, "origin: {} is not a valid fqdn", domain)
            }
            ParseRRErr::NoDefaultTTL => write!(format, "default ttl is not set"),
            ParseRRErr::NoOriginDomain => write!(format, "default origin domain is not set"),
            ParseRRErr::NoDefaultDomain => write!(format, "default domain is not set"),
            ParseRRErr::NoDomainType => write!(format, "default domain type is not set"),
            ParseRRErr::GeneralFail(err) => write!(format, "general error: {}", err),
            ParseRRErr::EmptyStrErr => write!(format, "empty zone data error"),
            _ => write!(format, "unknown error"),
        }
    }
}

impl From<ParseRRErr> for ParseZoneErr {
    fn from(cause: ParseRRErr) -> ParseZoneErr {
        ParseZoneErr::ParseZoneDataError(format!("parse rdata error: {}", cause))
    }
}

impl From<AddrParseError> for ParseRRErr {
    fn from(cause: AddrParseError) -> ParseRRErr {
        ParseRRErr::ParseTypeErr(cause.to_string())
    }
}
