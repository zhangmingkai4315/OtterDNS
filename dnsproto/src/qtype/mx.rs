use crate::dnsname::{parse_name, DNSName};
use crate::errors::{DNSProtoErr, ParseZoneDataErr};
use crate::meta::DNSType;
use crate::qtype::helper::not_space;
use crate::qtype::{CompressionType, DNSWireFrame};
use nom::character::complete::{digit1, multispace0};
use nom::number::complete::be_u16;
use std::any::Any;
use std::str::FromStr;
use std::{fmt, fmt::Formatter};

// https://tools.ietf.org/html/rfc1035#section-3.3.9
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                  PREFERENCE                   |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// /                   EXCHANGE                    /
// /                                               /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#[derive(Debug, PartialEq)]
pub struct DnsTypeMX {
    priority: u16,
    exchange: DNSName,
}

impl DnsTypeMX {
    pub fn new(priority: u16, exchange: &str) -> Result<Self, DNSProtoErr> {
        Ok(DnsTypeMX {
            priority,
            exchange: DNSName::new(exchange)?,
        })
    }
}

impl fmt::Display for DnsTypeMX {
    fn fmt(&self, format: &mut Formatter<'_>) -> fmt::Result {
        write!(format, "{} {}", self.priority, self.exchange.to_string())
    }
}
impl DNSWireFrame for DnsTypeMX {
    fn decode(data: &[u8], original: Option<&[u8]>) -> Result<Self, DNSProtoErr> {
        match parse_mx(data, original.unwrap_or(&[])) {
            Ok((_, mx)) => Ok(mx),
            Err(_err) => Err(DNSProtoErr::PacketParseError),
        }
    }

    fn get_type(&self) -> DNSType {
        DNSType::MX
    }

    fn encode(&self, compression: CompressionType) -> Result<Vec<u8>, DNSProtoErr> {
        let mut data = vec![];
        data.extend_from_slice(&self.priority.to_be_bytes()[..]);
        match compression {
            Some((compression_map, size)) => {
                let exchange = self.exchange.to_binary(Some((compression_map, size)));
                data.extend_from_slice(exchange.as_slice());
            }
            _ => {
                let exchange = self.exchange.to_binary(None);
                data.extend_from_slice(exchange.as_slice());
            }
        }
        Ok(data)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl FromStr for DnsTypeMX {
    type Err = ParseZoneDataErr;
    fn from_str(str: &str) -> Result<Self, Self::Err> {
        let (rest, priority) = digit1(str)?;
        let priority = u16::from_str(priority)?;
        let (rest, _) = multispace0(rest)?;
        let (_, exchange) = not_space(rest)?;
        Ok(DnsTypeMX {
            priority,
            exchange: DNSName::new(exchange)?,
        })
    }
}

named_args!(parse_mx<'a>(original: &[u8])<DnsTypeMX>,
    do_parse!(
        priority: be_u16>>
        exchange: call!(parse_name, original)>>
        (DnsTypeMX{
            exchange,
            priority,
        }
    )
));

#[cfg(test)]
mod test {
    use crate::label::Label;
    use crate::qtype::{DNSWireFrame, DnsTypeMX};
    use std::collections::HashMap;
    use std::str::FromStr;

    #[test]
    fn test_dns_type_mx() {
        let bin_arr = [
            0x00u8, 0x0f, 0x02, 0x6d, 0x78, 0x01, 0x6e, 0x06, 0x73, 0x68, 0x69, 0x66, 0x65, 0x6e,
            0x03, 0x63, 0x6f, 0x6d, 0x00,
        ];
        assert_eq!(
            DnsTypeMX::decode(&bin_arr, None).unwrap(),
            DnsTypeMX::new(15, "mx.n.shifen.com.").unwrap()
        );

        assert_eq!(
            "15 mx.n.shifen.com.".parse::<DnsTypeMX>().unwrap(),
            DnsTypeMX::new(15, "mx.n.shifen.com.").unwrap()
        );

        assert_eq!(
            "15 mx.n.shifen.com."
                .parse::<DnsTypeMX>()
                .unwrap()
                .encode(None)
                .unwrap(),
            &bin_arr,
        );
        let mut compression_map = HashMap::new();
        compression_map.insert(vec![Label::from_str("com").unwrap()], 12usize);
        let compressed_bin = [
            0x00u8, 0x0f, 0x02, 0x6d, 0x78, 0x01, 0x6e, 0x06, 0x73, 0x68, 0x69, 0x66, 0x65, 0x6e,
            0xc0, 0x0c,
        ];
        assert_eq!(
            "15 mx.n.shifen.com."
                .parse::<DnsTypeMX>()
                .unwrap()
                .encode(Some((&mut compression_map, 0)))
                .unwrap(),
            &compressed_bin,
        );
    }
}
