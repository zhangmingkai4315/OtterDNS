use crate::dnsname::parse_name;
use crate::meta::DNSType;
use crate::qtype::{CompressionType, DNSWireFrame, DnsTypeNS};
use otterlib::errors::DNSProtoErr;
use std::any::Any;
use std::fmt::{self, Formatter};

#[derive(Debug, PartialEq)]
pub struct DnsTypePTR(DnsTypeNS);

impl DnsTypePTR {
    pub fn new(name: &str) -> Result<Self, DNSProtoErr> {
        Ok(DnsTypePTR(DnsTypeNS::new(name)?))
    }
    pub(crate) fn from_str(
        a_str: &str,
        default_original: Option<&str>,
    ) -> Result<Self, DNSProtoErr> {
        Ok(DnsTypePTR(DnsTypeNS::from_str(a_str, default_original)?))
    }
}

impl fmt::Display for DnsTypePTR {
    fn fmt(&self, format: &mut Formatter<'_>) -> fmt::Result {
        write!(format, "{}", self.0.name.to_string())
    }
}

impl DNSWireFrame for DnsTypePTR {
    fn decode(data: &[u8], original: Option<&[u8]>) -> Result<Self, DNSProtoErr> {
        match parse_name(data, original.unwrap_or(&[])) {
            Ok((_, name)) => Ok(DnsTypePTR(DnsTypeNS { name })),
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
    use crate::qtype::{DNSWireFrame, DnsTypePTR};
    use std::collections::HashMap;
    use std::str::FromStr;

    #[test]
    fn test_ptr_decode() {
        let non_compression_vec: Vec<u8> = vec![
            1, 102, 12, 103, 116, 108, 100, 45, 115, 101, 114, 118, 101, 114, 115, 3, 110, 101,
            116, 0,
        ];
        let decode = DnsTypePTR::decode(non_compression_vec.as_slice(), None);
        assert_eq!(decode.is_ok(), true);
        assert_eq!(decode.unwrap().to_string(), "f.gtld-servers.net.");
    }
    #[test]
    fn test_ptr_encode() {
        let non_compression_vec: Vec<u8> = vec![
            1, 102, 12, 103, 116, 108, 100, 45, 115, 101, 114, 118, 101, 114, 115, 3, 110, 101,
            116, 0,
        ];
        let ptr_record = DnsTypePTR::new("f.gtld-servers.net.").unwrap();
        match ptr_record.encode(None) {
            Ok(ptr_record_u8) => assert_eq!(ptr_record_u8, non_compression_vec),
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
        match ptr_record.encode(Some((&mut compression_map, 30))) {
            Ok(ptr_data) => assert_eq!(ptr_data, compression_vec),
            _ => {
                assert!(false);
            }
        }
        let update_vec = vec![192, 30];
        match ptr_record.encode(Some((&mut compression_map, 0))) {
            Ok(ptr_data) => assert_eq!(ptr_data, update_vec),
            _ => {
                assert!(false);
            }
        }
    }
}
