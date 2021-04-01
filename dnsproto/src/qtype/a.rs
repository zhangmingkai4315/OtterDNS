use crate::errors::{DNSProtoErr, ParseZoneDataErr};
use crate::meta::DNSType;
use crate::qtype::{CompressionType, DNSWireFrame};
use std::any::Any;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::{fmt, fmt::Formatter};

#[derive(Debug, PartialOrd, PartialEq)]
pub struct DnsTypeA(Ipv4Addr);

impl DnsTypeA {
    pub fn new(ip: &str) -> Result<Self, DNSProtoErr> {
        Ok(DnsTypeA(Ipv4Addr::from_str(ip)?))
    }
}

impl fmt::Display for DnsTypeA {
    fn fmt(&self, format: &mut Formatter<'_>) -> fmt::Result {
        write!(format, "{}", self.0.to_string())
    }
}
impl DNSWireFrame for DnsTypeA {
    fn decode(data: &[u8], _: Option<&[u8]>) -> Result<Self, DNSProtoErr> {
        if data.len() < 4 {
            return Err(DNSProtoErr::PacketParseError);
        }
        let data = unsafe { &*(data as *const [u8] as *const [u8; 4]) };
        Ok(DnsTypeA(Ipv4Addr::from(*data)))
    }
    fn get_type(&self) -> DNSType {
        DNSType::A
    }

    fn encode(&self, _: CompressionType) -> Result<Vec<u8>, DNSProtoErr> {
        Ok(self.0.octets().to_vec())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl FromStr for DnsTypeA {
    type Err = ParseZoneDataErr;
    fn from_str(a_str: &str) -> Result<Self, Self::Err> {
        match a_str.parse::<Ipv4Addr>() {
            Ok(v4_addr) => Ok(DnsTypeA(v4_addr)),
            Err(err) => Err(ParseZoneDataErr::AddrParseError(err)),
        }
    }
}
#[cfg(test)]
mod test {
    use super::*;
    use crate::qtype::DNSWireFrame;

    #[test]
    fn test_dns_type_a() {
        assert_eq!(
            DnsTypeA::decode(&[0, 0, 0, 0], None).unwrap(),
            DnsTypeA(Ipv4Addr::new(0, 0, 0, 0))
        );
        assert_eq!(
            DnsTypeA::decode(&[127, 0, 0, 1], None).unwrap(),
            DnsTypeA(Ipv4Addr::new(127, 0, 0, 1))
        );
        assert_eq!(
            DnsTypeA::decode(&[255, 255, 255, 255], None).unwrap(),
            DnsTypeA(Ipv4Addr::new(255, 255, 255, 255))
        );

        assert_eq!(
            "1.2.3.4".parse::<DnsTypeA>().unwrap(),
            DnsTypeA::decode(&[1, 2, 3, 4], None).unwrap()
        );
        assert_eq!(
            "192.168.1.1".parse::<DnsTypeA>().unwrap(),
            DnsTypeA::decode(&[192, 168, 1, 1], None).unwrap()
        );
        assert_eq!(
            "127.0.0.1".parse::<DnsTypeA>().unwrap(),
            DnsTypeA::decode(&[127, 0, 0, 1], None).unwrap()
        );
        assert_eq!(
            "255.255.255.0".parse::<DnsTypeA>().unwrap(),
            DnsTypeA::decode(&[255, 255, 255, 0], None).unwrap()
        );

        for failed_ip in vec!["-1.-1.-2.-3", "256.256.265.23", "", "1.2.3", "1.2.3"] {
            match failed_ip.parse::<DnsTypeA>() {
                Err(ParseZoneDataErr::AddrParseError(_)) => {}
                _ => assert!(false, format!("parse {} should return error", failed_ip)),
            }
        }

        assert_eq!(
            "1.2.3.4".parse::<DnsTypeA>().unwrap().encode(None).unwrap(),
            &[1, 2, 3, 4]
        );
        assert_eq!(
            "192.168.1.1"
                .parse::<DnsTypeA>()
                .unwrap()
                .encode(None)
                .unwrap(),
            &[192, 168, 1, 1]
        );
        assert_eq!(
            "127.0.0.1"
                .parse::<DnsTypeA>()
                .unwrap()
                .encode(None)
                .unwrap(),
            &[127, 0, 0, 1]
        );
        assert_eq!(
            "255.255.255.0"
                .parse::<DnsTypeA>()
                .unwrap()
                .encode(None)
                .unwrap(),
            &[255, 255, 255, 0]
        );
    }
}
