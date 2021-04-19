use crate::dnsname::{parse_name, DNSName};
use crate::meta::DNSType;
use crate::qtype::{CompressionType, DNSWireFrame};
use otterlib::errors::DNSProtoErr;
use std::any::Any;
use std::fmt::{self, Formatter};

#[derive(Debug, PartialEq)]
pub struct DnsTypeNS {
    pub(crate) name: DNSName,
}

impl DnsTypeNS {
    pub fn new(name: &str) -> Result<DnsTypeNS, DNSProtoErr> {
        Ok(DnsTypeNS {
            name: DNSName::new(name, None)?,
        })
    }
    pub fn from_str(a_str: &str, default_original: Option<&str>) -> Result<Self, DNSProtoErr> {
        Ok(DnsTypeNS {
            name: DNSName::new(a_str, default_original)?,
        })
    }
    pub fn decode(data: &[u8], original: Option<&[u8]>) -> Result<Self, DNSProtoErr> {
        match parse_ns(data, original.unwrap_or(&[])) {
            Ok((_, ns)) => Ok(ns),
            Err(_err) => Err(DNSProtoErr::PacketParseError),
        }
    }
}

impl fmt::Display for DnsTypeNS {
    fn fmt(&self, format: &mut Formatter<'_>) -> fmt::Result {
        write!(format, "{}", self.name.to_string())
    }
}
named_args!(parse_ns<'a>(original: &[u8])<DnsTypeNS>,
    do_parse!(
        name: call!(parse_name, original)>>
        (DnsTypeNS{
            name,
        }
    )
));

impl DNSWireFrame for DnsTypeNS {
    fn get_type(&self) -> DNSType {
        DNSType::NS
    }
    fn encode(&self, compression: CompressionType) -> Result<Vec<u8>, DNSProtoErr> {
        Ok(self.name.to_binary(compression))
    }
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn clone_box(&self) -> Box<dyn DNSWireFrame> {
        Box::new(Self {
            name: self.name.clone(),
        })
    }
}
#[cfg(test)]
mod test {
    use crate::dnsname::DNSName;
    use crate::label::Label;
    use crate::qtype::{DNSWireFrame, DnsTypeNS};
    use std::collections::HashMap;
    use std::str::FromStr;

    #[test]
    fn test_ns_encode() {
        let non_compression_vec: Vec<u8> = vec![
            1, 102, 12, 103, 116, 108, 100, 45, 115, 101, 114, 118, 101, 114, 115, 3, 110, 101,
            116, 0,
        ];
        let ns = DnsTypeNS {
            name: DNSName::new("f.gtld-servers.net.", None).unwrap(),
        };
        match ns.encode(None) {
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
        match ns.encode(Some((&mut compression_map, 30))) {
            Ok(ns_data) => assert_eq!(ns_data, compression_vec),
            _ => {
                assert!(false);
            }
        }
        let update_vec = vec![192, 30];
        match ns.encode(Some((&mut compression_map, 0))) {
            Ok(ns_data) => assert_eq!(ns_data, update_vec),
            _ => {
                assert!(false);
            }
        }
    }
}
