use crate::dns::errors::ParseRRErr;
use crate::dns::utils::*;
use std::error::Error;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Deref;
use std::prelude::v1::Vec;
use std::rc::Rc;
use std::str::FromStr;

pub type DNSTypeResult<T> = std::result::Result<T, String>;

#[derive(Debug, Clone, PartialOrd, PartialEq)]
pub struct Label(Rc<[u8]>);
impl Label {
    pub fn from_bytes(bytes: &[u8]) -> DNSTypeResult<Self> {
        if bytes.len() > 63 {
            return Err(format!("exceeds max length {} >63 ", bytes.len()));
        }
        Ok(Label(Rc::from(bytes)))
    }
    pub fn from_str(s: &str) -> DNSTypeResult<Self> {
        if valid_label(s) {
            Ok(Label(Rc::from(s.as_bytes())))
        } else {
            Err(format!("label is not correct"))
        }
    }
}

#[derive(Debug, PartialOrd, PartialEq)]
struct DomainName {
    inner: Vec<Label>,
}

impl DomainName {
    fn to_string(&self) -> String {
        "".to_owned()
    }
}

#[derive(Debug, PartialOrd, PartialEq)]
pub struct DnsTypeA(Ipv4Addr);

impl DnsTypeA {
    pub fn from_binary(data: [u8; 4]) -> DnsTypeA {
        return DnsTypeA(Ipv4Addr::from(data));
    }
    pub fn to_binary(&self) -> [u8; 4] {
        self.0.octets()
    }
}

impl FromStr for DnsTypeA {
    type Err = ParseRRErr;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.parse::<Ipv4Addr>() {
            Ok(v) => return Ok(DnsTypeA(v)),
            Err(e) => return Err(ParseRRErr::from(e)),
        }
    }
}

#[test]
fn test_dns_type_a() {
    assert_eq!(
        DnsTypeA::from_binary([0, 0, 0, 0]),
        DnsTypeA(Ipv4Addr::new(0, 0, 0, 0))
    );
    assert_eq!(
        DnsTypeA::from_binary([127, 0, 0, 1]),
        DnsTypeA(Ipv4Addr::new(127, 0, 0, 1))
    );
    assert_eq!(
        DnsTypeA::from_binary([255, 255, 255, 255]),
        DnsTypeA(Ipv4Addr::new(255, 255, 255, 255))
    );

    assert_eq!(
        "1.2.3.4".parse::<DnsTypeA>().unwrap(),
        DnsTypeA::from_binary([1, 2, 3, 4])
    );
    assert_eq!(
        "192.168.1.1".parse::<DnsTypeA>().unwrap(),
        DnsTypeA::from_binary([192, 168, 1, 1])
    );
    assert_eq!(
        "127.0.0.1".parse::<DnsTypeA>().unwrap(),
        DnsTypeA::from_binary([127, 0, 0, 1])
    );
    assert_eq!(
        "255.255.255.0".parse::<DnsTypeA>().unwrap(),
        DnsTypeA::from_binary([255, 255, 255, 0])
    );

    assert_eq!(
        "1.2.3".parse::<DnsTypeA>().unwrap_err(),
        ParseRRErr::ParseTypeErr("invalid IP address syntax".to_owned())
    );
    assert_eq!(
        "".parse::<DnsTypeA>().unwrap_err(),
        ParseRRErr::ParseTypeErr("invalid IP address syntax".to_owned())
    );
    assert_eq!(
        "256.256.265.23".parse::<DnsTypeA>().unwrap_err(),
        ParseRRErr::ParseTypeErr("invalid IP address syntax".to_owned())
    );
    assert_eq!(
        "-1.-1.-2.-3".parse::<DnsTypeA>().unwrap_err(),
        ParseRRErr::ParseTypeErr("invalid IP address syntax".to_owned())
    );

    assert_eq!(
        "1.2.3.4".parse::<DnsTypeA>().unwrap().to_binary(),
        [1, 2, 3, 4]
    );
    assert_eq!(
        "192.168.1.1".parse::<DnsTypeA>().unwrap().to_binary(),
        [192, 168, 1, 1]
    );
    assert_eq!(
        "127.0.0.1".parse::<DnsTypeA>().unwrap().to_binary(),
        [127, 0, 0, 1]
    );
    assert_eq!(
        "255.255.255.0".parse::<DnsTypeA>().unwrap().to_binary(),
        [255, 255, 255, 0]
    );
}

#[derive(Debug, PartialOrd, PartialEq)]
pub struct DnsTypeAAAA(Ipv6Addr);

impl DnsTypeAAAA {
    pub fn from_binary(data: [u8; 16]) -> DnsTypeAAAA {
        return DnsTypeAAAA(Ipv6Addr::from(data));
    }
    pub fn to_binary(&self) -> [u8; 16] {
        self.0.octets()
    }
}

impl FromStr for DnsTypeAAAA {
    type Err = ParseRRErr;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.parse::<Ipv6Addr>() {
            Ok(v) => return Ok(DnsTypeAAAA(v)),
            Err(e) => return Err(ParseRRErr::from(e)),
        }
    }
}

#[test]
fn test_dns_type_aaaa() {
    assert_eq!(
        DnsTypeAAAA::from_binary([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        DnsTypeAAAA(Ipv6Addr::from_str("::").unwrap())
    );
    assert_eq!(
        DnsTypeAAAA::from_binary([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1]),
        DnsTypeAAAA(Ipv6Addr::from_str("::127.0.0.1").unwrap())
    );
    assert_eq!(
        DnsTypeAAAA::from_binary([255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 64, 32]),
        DnsTypeAAAA(Ipv6Addr::from_str("FF00::192.168.64.32").unwrap())
    );

    assert_eq!(
        DnsTypeAAAA::from_binary([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        "::".parse::<DnsTypeAAAA>().unwrap()
    );
    assert_eq!(
        DnsTypeAAAA::from_binary([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1]),
        "::127.0.0.1".parse::<DnsTypeAAAA>().unwrap()
    );
    assert_eq!(
        DnsTypeAAAA::from_binary([255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 64, 32]),
        "FF00::192.168.64.32".parse::<DnsTypeAAAA>().unwrap()
    );

    assert_eq!(
        "1.2.3".parse::<DnsTypeAAAA>().unwrap_err(),
        ParseRRErr::ParseTypeErr("invalid IP address syntax".to_owned())
    );
    assert_eq!(
        "::::".parse::<DnsTypeAAAA>().unwrap_err(),
        ParseRRErr::ParseTypeErr("invalid IP address syntax".to_owned())
    );
    assert_eq!(
        "FF00::192.168.64.32::".parse::<DnsTypeAAAA>().unwrap_err(),
        ParseRRErr::ParseTypeErr("invalid IP address syntax".to_owned())
    );
    assert_eq!(
        "::127.0.0.1::".parse::<DnsTypeAAAA>().unwrap_err(),
        ParseRRErr::ParseTypeErr("invalid IP address syntax".to_owned())
    );
}

// https://tools.ietf.org/html/rfc1035#section-3.3.13
//
// 3.3.13 SOA RDATA format
//
// ...
//
// MNAME           The <domain-name> of the name server that was the
// original or primary source of data for this zone.
//
// RNAME           A <domain-name> which specifies the mailbox of the
// person responsible for this zone.
//
// SERIAL          The unsigned 32 bit version number of the original copy
// of the zone.  Zone transfers preserve this value.  This
// value wraps and should be compared using sequence space
// arithmetic.
//
// REFRESH         A 32 bit time interval before the zone should be
// refreshed.
//
// RETRY           A 32 bit time interval that should elapse before a
// failed refresh should be retried.
//
// EXPIRE          A 32 bit time value that specifies the upper limit on
// the time interval that can elapse before the zone is no
// longer authoritative.
//
// MINIMUM         The unsigned 32 bit minimum TTL field that should be
// exported with any RR from this zone.
//
// SOA records cause no additional section processing.
//
// All times are in units of seconds.

#[derive(Debug, PartialOrd, PartialEq)]
pub struct DnsTypeSOA {
    m_name: DomainName,
    r_name: DomainName,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32,
}
