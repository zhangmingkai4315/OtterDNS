// The RDATA of the NSEC RR is as shown below:
//
// 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// /                      Next Domain Name                         /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// /                       Type Bit Maps                           /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// NSEC	aaa. NS SOA RRSIG NSEC DNSKEY

use crate::dnsname::{parse_name, DNSName};
use crate::meta::DNSType;
use crate::qtype::soa::is_not_space;
use crate::qtype::{CompressionType, DNSWireFrame};
use itertools::enumerate;
use nom::bytes::complete::take_while;
use nom::character::complete::multispace0;
use nom::combinator::rest;
use otterlib::errors::{DNSProtoErr, ParseZoneDataErr};
use std::any::Any;
use std::fmt;
use std::fmt::Formatter;

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
        let (rest, _) = multispace0(str)?;
        let (rest, next_domain) = take_while(is_not_space)(rest)?;
        let (rest, _) = multispace0(rest)?;
        let dnstypes = rest
            .split(" ")
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
        let type_arr = decode_nsec_from_bits(self.bitmaps.as_slice());
        let type_str = {
            match type_arr {
                Ok(val) => val
                    .iter()
                    .map(|v| {
                        DNSType::from_u16(*v)
                            .unwrap_or(DNSType::Unknown)
                            .to_string()
                    })
                    .collect::<Vec<String>>()
                    .join(" "),
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

fn decode_nsec_from_bits(input: &[u8]) -> Result<Vec<u16>, ParseZoneDataErr> {
    let mut result = Vec::new();
    let message_size = input.len();
    let mut offset = 0;
    let mut length: usize;
    let mut window: u8;
    let mut last_window = -1;
    while offset < message_size {
        if offset + 2 > message_size {
            return Err(ParseZoneDataErr::GeneralErr(
                "nsec block unpack overflow".to_string(),
            ));
        }
        window = input[offset];
        length = input[offset + 1] as usize;
        offset = offset + 2;
        if window as isize <= last_window {
            return Err(ParseZoneDataErr::GeneralErr(
                "nsec block unpack out of order".to_string(),
            ));
        }
        if length == 0 {
            return Err(ParseZoneDataErr::GeneralErr(
                "nsec block is empty".to_string(),
            ));
        }
        if length > 32 {
            return Err(ParseZoneDataErr::GeneralErr(
                "nsec block too long".to_string(),
            ));
        }
        if offset + length > message_size {
            return Err(ParseZoneDataErr::GeneralErr(
                "nsec block unpack overflow".to_string(),
            ));
        }
        for (index, block) in enumerate(input[offset..offset + length].iter()) {
            let index = index as u16;
            if block & 0x80 == 0x80 {
                result.push(window as u16 * 256 + index * 8 + 0)
            }
            if block & 0x40 == 0x40 {
                result.push(window as u16 * 256 + index * 8 + 1)
            }
            if block & 0x20 == 0x20 {
                result.push(window as u16 * 256 + index * 8 + 2)
            }
            if block & 0x10 == 0x10 {
                result.push(window as u16 * 256 + index * 8 + 3)
            }
            if block & 0x8 == 0x8 {
                result.push(window as u16 * 256 + index * 8 + 4)
            }
            if block & 0x4 == 0x4 {
                result.push(window as u16 * 256 + index * 8 + 5)
            }
            if block & 0x2 == 0x2 {
                result.push(window as u16 * 256 + index * 8 + 6)
            }
            if block & 0x1 == 0x1 {
                result.push(window as u16 * 256 + index * 8 + 7)
            }
        }
        offset += length;
        last_window = window as isize;
    }
    Ok(result)
}
fn encode_nsec_from_types(bitmap: Vec<DNSType>) -> Result<Vec<u8>, ParseZoneDataErr> {
    if bitmap.is_empty() {
        return Ok(vec![]);
    }
    let mut offset = 0;
    let mut last_window = 0u16;
    let mut last_length = 0u16;
    let mut result = vec![];
    for current in bitmap.iter() {
        let current = *current as u16;
        let window = current / 256;
        let length = (current - window * 256) / 8 + 1;
        if window > last_window && last_length != 0 {
            offset += last_length + 2;
            last_length = 0;
        }
        if window < last_window || length < last_length {
            return Err(ParseZoneDataErr::GeneralErr(
                "nsec bit out of order".to_string(),
            ));
        }
        let expected_length = (offset + 2 + length) as usize;
        if expected_length > result.len() {
            result.resize(expected_length, 0);
        }
        result[offset as usize] = window as u8;
        result[(offset + 1) as usize] = length as u8;
        result[(offset + 1 + length) as usize] |= 1 << (7 - current % 8);
        last_length = length;
        last_window = window;
    }
    // offset += last_window + 2;
    Ok(result)
}

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
