mod a;
mod aaaa;
mod ns;
mod opt;
mod soa;

use super::errors::DNSProtoErr;
use nom::lib::std::collections::HashMap;
use std::fmt::Debug;

use crate::errors::ParseZoneDataErr;
use crate::label::Label;
use crate::meta::DNSType;
pub use a::DnsTypeA;
pub use aaaa::DnsTypeAAAA;
use nom::lib::std::fmt::Display;
pub use ns::DnsTypeNS;
pub use opt::DNSTypeOpt;
pub use soa::DnsTypeSOA;
use std::str::FromStr;

// for wireframe convert
pub trait DNSWireFrame: Debug + Display {
    fn decode(data: &[u8], _: Option<&[u8]>) -> Result<Self, DNSProtoErr>
    where
        Self: Sized;
    fn get_type(&self)->DNSType;
    fn encode(
        &self,
        // frame: &mut Cursor<Vec<u8>>,
        compression: Option<(&mut HashMap<Vec<Label>, usize>, usize)>,
    ) -> Result<Vec<u8>, DNSProtoErr>;
}

pub fn decode_message_data<'a>(
    data: &'a [u8],
    original: &'a [u8],
    dtype: DNSType,
) -> Result<Box<dyn DNSWireFrame>, DNSProtoErr> {
    match dtype {
        DNSType::A => match DnsTypeA::decode(data, None) {
            Ok(val) => Ok(Box::new(val)),
            _ => Err(DNSProtoErr::PacketParseError),
        },
        DNSType::NS => match DnsTypeNS::decode(data, Some(original)) {
            Ok(val) => Ok(Box::new(val)),
            _ => Err(DNSProtoErr::PacketParseError),
        },
        DNSType::SOA => match DnsTypeSOA::decode(data, Some(original)) {
            Ok(val) => Ok(Box::new(val)),
            _ => Err(DNSProtoErr::PacketParseError),
        },
        DNSType::AAAA => match DnsTypeAAAA::decode(data, Some(original)) {
            Ok(val) => Ok(Box::new(val)),
            _ => Err(DNSProtoErr::PacketParseError),
        },
        DNSType::OPT => match DNSTypeOpt::decode(data, None) {
            Ok(val) => Ok(Box::new(val)),
            _ => Err(DNSProtoErr::PacketParseError),
        },
        _ => Err(DNSProtoErr::UnImplementedError),
    }
}

pub fn decode_dns_data_from_string(
    string: &str,
    dtype: DNSType,
) -> Result<Box<dyn DNSWireFrame>, ParseZoneDataErr> {
    match dtype {
        DNSType::A => match DnsTypeA::from_str(string) {
            Ok(dtype) => Ok(Box::new(dtype)),
            Err(err) => Err(err),
        },
        DNSType::AAAA => match DnsTypeAAAA::from_str(string) {
            Ok(dtype) => Ok(Box::new(dtype)),
            Err(err) => Err(err),
        },
        DNSType::NS => match DnsTypeNS::from_str(string) {
            Ok(dtype) => Ok(Box::new(dtype)),
            Err(err) => Err(err),
        },
        DNSType::SOA => match DnsTypeSOA::from_str(string) {
            Ok(dtype) => Ok(Box::new(dtype)),
            Err(err) => Err(err),
        },
        _ => Err(ParseZoneDataErr::UnimplementedErr),
    }
}
