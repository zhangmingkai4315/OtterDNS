use std::fmt;
use std::fmt::Formatter;
use std::net::AddrParseError;


#[derive(Debug, PartialEq, Clone)]
pub enum ApplicationErr {
    PacketParseError,
}

#[derive(Debug, PartialEq, Clone)]
pub enum ParseZoneErr {
    FileNotExist(String),
    ReadFileError(String),
    ParseZoneDataError(String),
}

impl fmt::Display for ParseZoneErr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            ParseZoneErr::FileNotExist(ref file_path) => write!(f, "file: {} not exist", file_path),
            ParseZoneErr::ReadFileError(ref err) => write!(f, "read file error: {}", err),
            ParseZoneErr::ParseZoneDataError(ref err) => write!(f, "zone parse error: {}", err),
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
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ParseRRErr::ValidDomainErr(domain) => write!(f, "domain: {} is not valid", domain),
            ParseRRErr::ValidOriginErr(domain) => {
                write!(f, "origin: {} is not a valid fqdn", domain)
            }
            ParseRRErr::NoDefaultTTL => write!(f, "default ttl is not set"),
            ParseRRErr::NoOriginDomain => write!(f, "default origin domain is not set"),
            ParseRRErr::NoDefaultDomain => write!(f, "default domain is not set"),
            ParseRRErr::NoDomainType => write!(f, "default domain type is not set"),
            ParseRRErr::GeneralFail(err) => write!(f, "general error: {}", err),
            ParseRRErr::EmptyStrErr => write!(f, "empty zone data error"),
            _ => write!(f, "unknown error"),
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
