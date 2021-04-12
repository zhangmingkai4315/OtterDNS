// The RDATA of the NSEC RR is as shown below:
//
// 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// /                      Next Domain Name                         /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// /                       Type Bit Maps                           /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
use crate::dnsname::{parse_name, DNSName};
use crate::meta::DNSType;
use crate::qtype::helper::{encode_nsec_from_types, nsec_bits_to_string};
use crate::qtype::soa::is_not_space;
use crate::qtype::{CompressionType, DNSWireFrame};
use nom::bytes::complete::take_while;
use nom::character::complete::multispace0;
use nom::combinator::rest;
use otterlib::errors::{DNSProtoErr, ParseZoneDataErr};
use std::any::Any;
use std::fmt::{self, Formatter};

#[derive(Debug, PartialEq)]
pub struct DnsTypeNSEC {
    next_domain: DNSName,
    bitmaps: Vec<u8>,
}

impl DnsTypeNSEC {
    pub fn new(domain: &str, type_arr: Vec<DNSType>) -> Result<Self, DNSProtoErr> {
        Ok(DnsTypeNSEC {
            next_domain: DNSName::new(domain, None)?,
            bitmaps: encode_nsec_from_types(type_arr)?,
        })
    }
    // aaa. NS SOA RRSIG NSEC DNSKEY
    pub fn from_str(str: &str, default_original: Option<&str>) -> Result<Self, ParseZoneDataErr> {
        let (rest, next_domain) = take_while(is_not_space)(str)?;
        let (rest, _) = multispace0(rest)?;
        let dnstypes = rest
            .split(' ')
            .into_iter()
            .map(|dtype| DNSType::from_str(dtype).unwrap_or(DNSType::Unknown))
            .collect();
        let bitmaps = encode_nsec_from_types(dnstypes)?;
        Ok(DnsTypeNSEC {
            next_domain: DNSName::new(next_domain, default_original)?,
            bitmaps,
        })
    }
}

impl fmt::Display for DnsTypeNSEC {
    fn fmt(&self, format: &mut Formatter<'_>) -> fmt::Result {
        let type_str = {
            match nsec_bits_to_string(self.bitmaps.as_slice()) {
                Ok(nsec_result) => nsec_result,
                Err(err) => format!("decode fail: {:?}", err),
            }
        };
        write!(format, "{} {}", self.next_domain, type_str)
    }
}
impl DNSWireFrame for DnsTypeNSEC {
    fn decode(data: &[u8], original: Option<&[u8]>) -> Result<Self, DNSProtoErr> {
        match parse_nsec(data, original.unwrap_or(&[])) {
            Ok((_, nsec)) => Ok(nsec),
            Err(_err) => Err(DNSProtoErr::PacketParseError),
        }
    }

    fn get_type(&self) -> DNSType {
        DNSType::NSEC
    }

    fn encode(&self, compression: CompressionType) -> Result<Vec<u8>, DNSProtoErr> {
        let mut data = vec![];

        match compression {
            Some((compression_map, size)) => {
                let exchange = self.next_domain.to_binary(Some((compression_map, size)));
                data.extend_from_slice(exchange.as_slice());
            }
            _ => {
                let exchange = self.next_domain.to_binary(None);
                data.extend_from_slice(exchange.as_slice());
            }
        }
        data.extend_from_slice(self.bitmaps.as_slice());
        Ok(data)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

named_args!(parse_nsec<'a>(original: &[u8])<DnsTypeNSEC>,
    do_parse!(
        next_domain: call!(parse_name, original)>>
        bitmaps: call!(rest)>>
        (DnsTypeNSEC{
            next_domain,
            bitmaps: bitmaps.to_vec(),
        }
    )
));

#[cfg(test)]
mod test {
    use crate::meta::DNSType;
    use crate::qtype::nsec::DnsTypeNSEC;
    use crate::qtype::DNSWireFrame;

    fn get_example_nsec() -> (Vec<u8>, String, DnsTypeNSEC) {
        let nsec_str = "aaa. NS SOA RRSIG NSEC DNSKEY";
        let nsec_struct = DnsTypeNSEC::new(
            "aaa.",
            vec![
                DNSType::NS,
                DNSType::SOA,
                DNSType::RRSIG,
                DNSType::NSEC,
                DNSType::DNSKEY,
            ],
        );
        let nsec_bitstream = vec![
            0x03, 0x61, 0x61, 0x61, 0x00, 0x00, 0x07, 0x22, 0x00, 0x00, 0x00, 0x00, 0x03, 0x80,
        ];
        (nsec_bitstream, nsec_str.to_owned(), nsec_struct.unwrap())
    }

    #[test]
    fn dns_nsec_parser_str() {
        let arr = vec![
            "tui. NS DS RRSIG NSEC",
            "tv. NS DS RRSIG NSEC",
            "xn--5su34j936bgsg. NS DS RRSIG NSEC",
            "xn--b4w605ferd. NS DS RRSIG NSEC",
            "xn--w4rs40l. NS DS RRSIG NSEC",
        ];
        for item in arr.iter() {
            let result = DnsTypeNSEC::from_str(item, None);
            assert_eq!(result.is_ok(), true);
        }
    }

    #[test]
    fn dns_nsec_from_str() {
        let (_, nsec_str, nsec_struct) = get_example_nsec();
        match DnsTypeNSEC::from_str(nsec_str.as_str(), None) {
            Ok(nsec) => {
                assert_eq!(nsec, nsec_struct);
            }
            Err(err) => assert!(
                false,
                format!("nsec from_str method got a unexpected failure: {:?}", err)
            ),
        }
    }

    #[test]
    fn nsec_binary_serialize() {
        let (bin_arr, nsec_str, nsec_struct) = get_example_nsec();
        assert_eq!(DnsTypeNSEC::decode(&bin_arr, None).unwrap(), nsec_struct);
        match nsec_struct.encode(None) {
            Ok(nsec_vec) => {
                assert_eq!(nsec_vec.as_slice(), &bin_arr[..]);
            }
            _ => assert!(false, "encode nsec fail"),
        }
        assert_eq!(nsec_str, nsec_struct.to_string());
    }
}
