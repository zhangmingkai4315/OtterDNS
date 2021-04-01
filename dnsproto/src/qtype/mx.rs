use crate::errors::{DNSProtoErr, ParseZoneDataErr};
use crate::label::Label;
use crate::qtype::DNSWireFrame;
use nom::lib::std::collections::hash_map::RandomState;
use std::collections::HashMap;
use std::str::FromStr;
use std::{fmt, fmt::Formatter};
use crate::meta::DNSType;
use nom::character::complete::{digit1, multispace0};
use nom::bytes::streaming::take_while;
use crate::qtype::soa::is_not_space;
use nom::number::complete::be_u16;
use crate::dnsname::{parse_name, DNSName};

#[derive(Debug, PartialEq)]
pub struct DnsTypeMX{
    priority:  u16,
    exchange:  DNSName,
}

impl DnsTypeMX {
    pub fn new(priority: u16, exchange: &str) -> Result<Self, DNSProtoErr> {
        Ok(DnsTypeMX{
            priority,
            exchange: DNSName::new(exchange)?
        })
    }
}

impl fmt::Display for DnsTypeMX {
    fn fmt(&self, format: &mut Formatter<'_>) -> fmt::Result {
        write!(format, "{} {}",self.priority, self.exchange.to_string())
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

    fn encode(
        &self,
        compression: Option<(&mut HashMap<Vec<Label>, usize, RandomState>, usize)>,
    ) -> Result<Vec<u8>, DNSProtoErr> {
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
}

impl FromStr for DnsTypeMX {
    type Err = ParseZoneDataErr;
    fn from_str(str: &str) -> Result<Self, Self::Err> {
        let (rest, priority) = digit1(str)?;
        let priority = u16::from_str(priority)?;
        let (rest, _) = multispace0(rest)?;
        let (_, exchange) = take_while(is_not_space)(rest)?;
        Ok(DnsTypeMX {
            priority,
            exchange: DNSName::new(exchange)?
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