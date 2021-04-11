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

use crate::dnsname::DNSName;
use crate::meta::DNSType;
use crate::qtype::{CompressionType, DNSWireFrame, DnsTypeMX, DnsTypeNS};
use itertools::enumerate;
use otterlib::errors::{DNSProtoErr, ParseZoneDataErr};
use std::any::Any;
use std::convert::TryFrom;
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
    // NSEC	aaa. NS SOA RRSIG NSEC DNSKEY
    // pub fn from_str(str: &str, default_original: Option<&str>) -> Result<Self, ParseZoneDataErr> {
    //     let (rest, priority) = digit1(str)?;
    //     let priority = u16::from_str(priority)?;
    //     let (rest, _) = multispace0(rest)?;
    //     let (_, exchange) = not_space(rest)?;
    //     Ok(DnsTypeMX {
    //         priority,
    //         exchange: DNSName::new(exchange, default_original)?,
    //     })
    // }
}

impl fmt::Display for DnsTypeNSEC {
    fn fmt(&self, format: &mut Formatter<'_>) -> fmt::Result {
        let type_arr = decode_nsec_from_bits(self.bitmaps.as_slice());
        let type_str = {
            match type_arr {
                Ok(val) => val
                    .iter()
                    .map(|v| DNSType::try_from(v).to_string())
                    .collect(),
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

    // fn encode(&self, compression: CompressionType) -> Result<Vec<u8>, DNSProtoErr> {
    //     let mut data = vec![];
    //     data.extend_from_slice(&self.priority.to_be_bytes()[..]);
    //     match compression {
    //         Some((compression_map, size)) => {
    //             let exchange = self.exchange.to_binary(Some((compression_map, size)));
    //             data.extend_from_slice(exchange.as_slice());
    //         }
    //         _ => {
    //             let exchange = self.exchange.to_binary(None);
    //             data.extend_from_slice(exchange.as_slice());
    //         }
    //     }
    //     Ok(data)
    // }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

named_args!(parse_nsec<'a>(original: &[u8])<DnsTypeNSEC>,
    do_parse!(
        priority: be_u16>>
        exchange: call!(parse_name, original)>>
        (DnsTypeNSEC{
            exchange,
            priority,
        }
    )
));

fn decode_nsec_from_bits(input: &[u8]) -> Result<Vec<u16>, ParseZoneDataErr> {
    let mut result = Vec::new();
    let message_size = input.len();
    let mut offset = 0;
    let mut length = 0;
    let mut window = 0;
    let mut last_window = -1;
    while offset < message_size {
        if offset + 2 > message_size {
            return Err(ParseZoneDataErr::GeneralErr(
                "nsec block unpack overflow".to_string(),
            ));
        }
        window = input[offset];
        length = input[offset + 1];
        if window <= last_window {
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
            match block {
                block if block & 0x80 == 0x80 => result.push(window as u16 * 256 + index * 8 + 0),
                block if block & 0x40 == 0x40 => result.push(window as u16 * 256 + index * 8 + 1),
                block if block & 0x20 == 0x20 => result.push(window as u16 * 256 + index * 8 + 2),
                block if block & 0x10 == 0x10 => result.push(window as u16 * 256 + index * 8 + 3),
                block if block & 0x8 == 0x8 => result.push(window as u16 * 256 + index * 8 + 4),
                block if block & 0x4 == 0x4 => result.push(window as u16 * 256 + index * 8 + 5),
                block if block & 0x2 == 0x2 => result.push(window as u16 * 256 + index * 8 + 6),
                block if block & 0x1 == 0x1 => result.push(window as u16 * 256 + index * 8 + 7),
                _ => {}
            }
        }
        offset += length;
        last_window = window;
    }
    Ok(result)
}
fn encode_nsec_from_types(bitmap: Vec<DNSType>) -> Result<Vec<u8>, ParseZoneDataErr> {
    if bitmap.is_empty() {
        Ok(vec![])
    }
    let mut offset = 0;
    let mut last_window = 0u16;
    let mut last_length = 0u16;
    let mut result = vec![];
    for current in bitmap.iter() {
        let current = current as u16;
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
        result[offset] = window as u8;
        result[offset + 1] = length as u8;
        result[offset + 1 + length] |= 1 << (7 - current % 8);
        last_length = length;
        last_window = window;
    }
    offset += last_window + 2;
    Ok(result)
}

#[cfg(test)]
mod test {}
