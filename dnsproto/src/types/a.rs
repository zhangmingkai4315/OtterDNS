use crate::errors::{PacketProcessErr, ParseRRErr};
use crate::types::DNSFrame;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::{fmt, fmt::Formatter};

#[derive(Debug, PartialOrd, PartialEq)]
pub struct DnsTypeA(Ipv4Addr);

impl DNSFrame for DnsTypeA {
    type Item = Self;
    fn decode(data: &[u8]) -> Result<Self::Item, PacketProcessErr> {
        if data.len() < 4 {
            return Err(PacketProcessErr::PacketParseError);
        }
        let data = unsafe { &*(data as *const [u8] as *const [u8; 4]) };
        Ok(DnsTypeA(Ipv4Addr::from(*data)))
    }

    fn encode(&self) -> Result<Vec<u8>, PacketProcessErr> {
        Ok(self.0.octets().to_vec())
    }
}

impl FromStr for DnsTypeA {
    type Err = ParseRRErr;
    fn from_str(a_str: &str) -> Result<Self, Self::Err> {
        match a_str.parse::<Ipv4Addr>() {
            Ok(v4_addr) => Ok(DnsTypeA(v4_addr)),
            Err(err) => Err(ParseRRErr::from(err)),
        }
    }
}

impl fmt::Display for DnsTypeA {
    fn fmt(&self, format: &mut Formatter<'_>) -> fmt::Result {
        write!(format, "{}", self.0.to_string())
    }
}

#[test]
fn test_dns_type_a() {
    assert_eq!(
        DnsTypeA::decode(&[0, 0, 0, 0]).unwrap(),
        DnsTypeA(Ipv4Addr::new(0, 0, 0, 0))
    );
    assert_eq!(
        DnsTypeA::decode(&[127, 0, 0, 1]).unwrap(),
        DnsTypeA(Ipv4Addr::new(127, 0, 0, 1))
    );
    assert_eq!(
        DnsTypeA::decode(&[255, 255, 255, 255]).unwrap(),
        DnsTypeA(Ipv4Addr::new(255, 255, 255, 255))
    );

    assert_eq!(
        "1.2.3.4".parse::<DnsTypeA>().unwrap(),
        DnsTypeA::decode(&[1, 2, 3, 4]).unwrap()
    );
    assert_eq!(
        "192.168.1.1".parse::<DnsTypeA>().unwrap(),
        DnsTypeA::decode(&[192, 168, 1, 1]).unwrap()
    );
    assert_eq!(
        "127.0.0.1".parse::<DnsTypeA>().unwrap(),
        DnsTypeA::decode(&[127, 0, 0, 1]).unwrap()
    );
    assert_eq!(
        "255.255.255.0".parse::<DnsTypeA>().unwrap(),
        DnsTypeA::decode(&[255, 255, 255, 0]).unwrap()
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
        "1.2.3.4".parse::<DnsTypeA>().unwrap().encode().unwrap(),
        &[1, 2, 3, 4]
    );
    assert_eq!(
        "192.168.1.1".parse::<DnsTypeA>().unwrap().encode().unwrap(),
        &[192, 168, 1, 1]
    );
    assert_eq!(
        "127.0.0.1".parse::<DnsTypeA>().unwrap().encode().unwrap(),
        &[127, 0, 0, 1]
    );
    assert_eq!(
        "255.255.255.0"
            .parse::<DnsTypeA>()
            .unwrap()
            .encode()
            .unwrap(),
        &[255, 255, 255, 0]
    );
}
