use crate::dnsname::{parse_name, DNSName};
use crate::errors::DNSProtoErr;
use crate::qtype::DNSWireFrame;
use nom::lib::std::collections::HashMap;

#[derive(Debug, PartialEq)]
pub struct DnsTypeNS {
    pub(crate) ns: DNSName,
}

impl DnsTypeNS {
    pub fn new(name: &str) -> Result<DnsTypeNS, DNSProtoErr> {
        Ok(DnsTypeNS {
            ns: DNSName::new(name)?,
        })
    }
}

named_args!(parse_ns<'a>(original: &[u8])<DnsTypeNS>,
    do_parse!(
        ns: call!(parse_name, original)>>
        (DnsTypeNS{
            ns,
        }
    )
));

impl DNSWireFrame for DnsTypeNS {
    fn decode(data: &[u8], original: Option<&[u8]>) -> Result<Self, DNSProtoErr> where Self:Sized
    {
        match parse_ns(data, original.unwrap_or(&[])) {
            Ok((_, ns)) => Ok(ns),
            Err(_err) => Err(DNSProtoErr::PacketParseError),
        }
    }
    fn encode(
        &self,
        compression: Option<(&mut HashMap<String, usize>, usize)>,
    ) -> Result<Vec<u8>, DNSProtoErr> {
        Ok(self.ns.to_binary(compression))
    }
}

#[test]
fn test_ns_encode() {
    let non_compression_vec: Vec<u8> = vec![
        1, 102, 12, 103, 116, 108, 100, 45, 115, 101, 114, 118, 101, 114, 115, 3, 110, 101, 116, 0,
    ];
    let ns = DnsTypeNS {
        ns: DNSName::new("f.gtld-servers.net").unwrap(),
    };
    match ns.encode(None) {
        Ok(ns_data) => assert_eq!(ns_data, non_compression_vec),
        _ => {
            assert!(false);
        }
    }
    let mut compression_map = HashMap::new();
    compression_map.insert("gtld-servers.net".to_owned(), 23);
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

