use crate::dns::errors::{ParseRRErr, PacketProcessErr};
use std::net::{Ipv6Addr};
use std::str::FromStr;
use super::BinaryConverter;

#[derive(Debug, PartialOrd, PartialEq)]
pub struct DnsTypeAAAA(Ipv6Addr);

impl BinaryConverter for DnsTypeAAAA {
    type Err = PacketProcessErr;
    fn from_binary(data: &[u8]) -> Result<DnsTypeAAAA,  PacketProcessErr> {
        if data.len() < 16 {
            return Err(PacketProcessErr::PacketParseError)
        }
        let data = unsafe { &*(data as *const [u8] as *const [u8; 16]) };
        Ok(DnsTypeAAAA(Ipv6Addr::from(*data)))
    }
    fn to_binary(&self) ->Result<Vec<u8>, Self::Err> {
        Ok(self.0.octets().to_vec())
    }
}

impl FromStr for DnsTypeAAAA {
    type Err = ParseRRErr;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        return match s.parse::<Ipv6Addr>() {
            Ok(v) => Ok(DnsTypeAAAA(v)),
            Err(e) => Err(ParseRRErr::from(e)),
        }
    }
}

#[test]
fn test_dns_type_aaaa() {
    assert_eq!(
        DnsTypeAAAA::from_binary(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        Ok(DnsTypeAAAA(Ipv6Addr::from_str("::").unwrap()))
    );
    assert_eq!(
        DnsTypeAAAA::from_binary(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1]),
        Ok(DnsTypeAAAA(Ipv6Addr::from_str("::127.0.0.1").unwrap()))
    );
    assert_eq!(
        DnsTypeAAAA::from_binary(&[255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 64, 32]),
        Ok(DnsTypeAAAA(Ipv6Addr::from_str("FF00::192.168.64.32").unwrap()))
    );

    assert_eq!(
        DnsTypeAAAA::from_binary(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
        "::".parse::<DnsTypeAAAA>().unwrap()
    );
    assert_eq!(
        DnsTypeAAAA::from_binary(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1]).unwrap(),
        "::127.0.0.1".parse::<DnsTypeAAAA>().unwrap()
    );
    assert_eq!(
        DnsTypeAAAA::from_binary(&[255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 64, 32]).unwrap(),
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
