use crate::dnsname::parse_name;
use crate::errors::{DNSProtoErr, ParseZoneDataErr};
use crate::meta::DNSType;
use crate::qtype::{CompressionType, DNSWireFrame, DnsTypeNS};
use std::any::Any;
use std::fmt::{self, Formatter};
use std::str::FromStr;

#[derive(Debug, PartialEq)]
pub struct DnsTypeCNAME(DnsTypeNS);

impl FromStr for DnsTypeCNAME {
    type Err = ParseZoneDataErr;
    fn from_str(a_str: &str) -> Result<Self, Self::Err> {
        Ok(DnsTypeCNAME(DnsTypeNS::from_str(a_str)?))
    }
}

impl DnsTypeCNAME {
    pub fn new(name: &str) -> Result<Self, DNSProtoErr> {
        Ok(DnsTypeCNAME(DnsTypeNS::new(name)?))
    }
}

impl fmt::Display for DnsTypeCNAME {
    fn fmt(&self, format: &mut Formatter<'_>) -> fmt::Result {
        write!(format, "{}", self.0.name.to_string())
    }
}

impl DNSWireFrame for DnsTypeCNAME {
    fn decode(data: &[u8], original: Option<&[u8]>) -> Result<Self, DNSProtoErr> {
        match parse_name(data, original.unwrap_or(&[])) {
            Ok((_, name)) => Ok(DnsTypeCNAME(DnsTypeNS { name })),
            Err(_err) => Err(DNSProtoErr::PacketParseError),
        }
    }
    fn get_type(&self) -> DNSType {
        DNSType::CNAME
    }
    fn encode(&self, compression: CompressionType) -> Result<Vec<u8>, DNSProtoErr> {
        Ok(self.0.name.to_binary(compression))
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
#[cfg(test)]
mod test {
    use crate::label::Label;
    use crate::qtype::{DNSWireFrame, DnsTypeCNAME};
    use std::collections::HashMap;
    use std::str::FromStr;
    #[test]
    fn test_cname_decode() {
        let non_compression_vec: Vec<u8> = vec![
            1, 102, 12, 103, 116, 108, 100, 45, 115, 101, 114, 118, 101, 114, 115, 3, 110, 101,
            116, 0,
        ];
        let decode = DnsTypeCNAME::decode(non_compression_vec.as_slice(), None);
        assert_eq!(decode.is_ok(), true);
        assert_eq!(decode.unwrap().to_string(), "f.gtld-servers.net.");
    }
    #[test]
    fn test_cname_encode() {
        let non_compression_vec: Vec<u8> = vec![
            1, 102, 12, 103, 116, 108, 100, 45, 115, 101, 114, 118, 101, 114, 115, 3, 110, 101,
            116, 0,
        ];
        let cname = DnsTypeCNAME::new("f.gtld-servers.net").unwrap();
        match cname.encode(None) {
            Ok(ns_data) => assert_eq!(ns_data, non_compression_vec),
            _ => {
                assert!(false);
            }
        }
        let mut compression_map = HashMap::new();
        compression_map.insert(
            vec![
                Label::from_str("gtld-servers").unwrap(),
                Label::from_str("net").unwrap(),
            ],
            23,
        );
        let compression_vec: Vec<u8> = vec![1, 102, 192, 23];
        match cname.encode(Some((&mut compression_map, 30))) {
            Ok(ns_data) => assert_eq!(ns_data, compression_vec),
            _ => {
                assert!(false);
            }
        }
        let update_vec = vec![192, 30];
        match cname.encode(Some((&mut compression_map, 0))) {
            Ok(ns_data) => assert_eq!(ns_data, update_vec),
            _ => {
                assert!(false);
            }
        }
    }
}
