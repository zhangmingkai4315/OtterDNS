use crate::errors::{DNSProtoErr, ParseZoneDataErr};
use crate::qtype::DNSWireFrame;
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::str::FromStr;
use std::{fmt, fmt::Formatter};

#[derive(Debug, PartialOrd, PartialEq)]
pub struct DnsTypeAAAA(Ipv6Addr);

impl DNSWireFrame for DnsTypeAAAA {
    fn decode(data: &[u8], _: Option<&[u8]>) -> Result<Self, DNSProtoErr>  where Self:Sized{
        if data.len() < 16 {
            return Err(DNSProtoErr::PacketParseError);
        }
        let data = unsafe { &*(data as *const [u8] as *const [u8; 16]) };
        Ok(DnsTypeAAAA(Ipv6Addr::from(*data)))
    }
    fn encode(
        &self,
        _: Option<(&mut HashMap<String, usize>, usize)>,
    ) -> Result<Vec<u8>, DNSProtoErr> {
        Ok(self.0.octets().to_vec())
    }
}

impl FromStr for DnsTypeAAAA {
    type Err = ParseZoneDataErr;
    fn from_str(aaaa_str: &str) -> Result<Self, Self::Err> {
        match aaaa_str.parse::<Ipv6Addr>() {
            Ok(v6_addr) => Ok(DnsTypeAAAA(v6_addr)),
            Err(err) => Err(ParseZoneDataErr::AddrParseError(err)),
        }
    }
}

impl fmt::Display for DnsTypeAAAA {
    fn fmt(&self, format: &mut Formatter<'_>) -> fmt::Result {
        write!(format, "{}", self.0.to_string())
    }
}

#[test]
fn test_dns_type_aaaa() {
    assert_eq!(
        DnsTypeAAAA::decode(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], None),
        Ok(DnsTypeAAAA(Ipv6Addr::from_str("::").unwrap()))
    );
    assert_eq!(
        DnsTypeAAAA::decode(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1], None),
        Ok(DnsTypeAAAA(Ipv6Addr::from_str("::127.0.0.1").unwrap()))
    );
    assert_eq!(
        DnsTypeAAAA::decode(
            &[255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 64, 32],
            None
        ),
        Ok(DnsTypeAAAA(
            Ipv6Addr::from_str("FF00::192.168.64.32").unwrap()
        ))
    );

    assert_eq!(
        DnsTypeAAAA::decode(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], None).unwrap(),
        "::".parse::<DnsTypeAAAA>().unwrap()
    );
    assert_eq!(
        DnsTypeAAAA::decode(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1], None).unwrap(),
        "::127.0.0.1".parse::<DnsTypeAAAA>().unwrap()
    );
    assert_eq!(
        DnsTypeAAAA::decode(
            &[255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 64, 32],
            None
        )
        .unwrap(),
        "FF00::192.168.64.32".parse::<DnsTypeAAAA>().unwrap()
    );

    for failed_ip in vec![
        "::::",
        "1234",
        "1.2.3.4",
        "FF00::192.168.64.32::",
        "::127.0.0.1::",
    ] {
        match failed_ip.parse::<DnsTypeAAAA>() {
            Err(ParseZoneDataErr::AddrParseError(_)) => {}
            _ => assert!(false, format!("parse {} should return error", failed_ip)),
        }
    }
}
