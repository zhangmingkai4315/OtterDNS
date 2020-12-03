use crate::dns::errors::{ParseRRErr, PacketProcessErr};
use std::net::{Ipv4Addr};
use std::str::FromStr;
use super::{BinaryConverter};

#[derive(Debug, PartialOrd, PartialEq)]
pub struct DnsTypeA(Ipv4Addr);
use std::convert::TryFrom;

impl BinaryConverter for DnsTypeA {
    type Err = PacketProcessErr;
    fn from_binary(data: &[u8]) -> Result<DnsTypeA,  PacketProcessErr> {
        if data.len() < 4 {
            return Err(PacketProcessErr::PacketParseError)
        }
        let data = unsafe { &*(data as *const [u8] as *const [u8; 4]) };
        return Ok(DnsTypeA(Ipv4Addr::from(*data)));
    }
    fn to_binary(&self) ->Result<Vec<u8>, Self::Err> {
        Ok(self.0.octets().to_vec())
    }
}

impl FromStr for DnsTypeA {
    type Err = ParseRRErr;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.parse::<Ipv4Addr>() {
            Ok(v) => Ok(DnsTypeA(v)),
            Err(e) => Err(ParseRRErr::from(e)),
        }
    }
}

#[test]
fn test_dns_type_a() {
    assert_eq!(
        DnsTypeA::from_binary(&[0, 0, 0, 0]).unwrap(),
        DnsTypeA(Ipv4Addr::new(0, 0, 0, 0))
    );
    assert_eq!(
        DnsTypeA::from_binary(&[127, 0, 0, 1]).unwrap(),
        DnsTypeA(Ipv4Addr::new(127, 0, 0, 1))
    );
    assert_eq!(
        DnsTypeA::from_binary(&[255, 255, 255, 255]).unwrap(),
        DnsTypeA(Ipv4Addr::new(255, 255, 255, 255))
    );

    assert_eq!(
        "1.2.3.4".parse::<DnsTypeA>().unwrap(),
        DnsTypeA::from_binary(&[1, 2, 3, 4]).unwrap()
    );
    assert_eq!(
        "192.168.1.1".parse::<DnsTypeA>().unwrap(),
        DnsTypeA::from_binary(&[192, 168, 1, 1]).unwrap()
    );
    assert_eq!(
        "127.0.0.1".parse::<DnsTypeA>().unwrap(),
        DnsTypeA::from_binary(&[127, 0, 0, 1]).unwrap()
    );
    assert_eq!(
        "255.255.255.0".parse::<DnsTypeA>().unwrap(),
        DnsTypeA::from_binary(&[255, 255, 255, 0]).unwrap()
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
        "1.2.3.4".parse::<DnsTypeA>().unwrap().to_binary().unwrap(),
        &[1, 2, 3, 4]
    );
    assert_eq!(
        "192.168.1.1".parse::<DnsTypeA>().unwrap().to_binary().unwrap(),
        &[192, 168, 1, 1]
    );
    assert_eq!(
        "127.0.0.1".parse::<DnsTypeA>().unwrap().to_binary().unwrap(),
        &[127, 0, 0, 1]
    );
    assert_eq!(
        "255.255.255.0".parse::<DnsTypeA>().unwrap().to_binary().unwrap(),
        &[255, 255, 255, 0]
    );
}
