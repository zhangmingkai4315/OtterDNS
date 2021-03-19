mod a;
mod aaaa;
mod ns;
mod opt;
mod soa;

use super::errors::DNSProtoErr;
use nom::lib::std::collections::HashMap;
use std::fmt::Debug;

pub use a::DnsTypeA;
pub use aaaa::DnsTypeAAAA;
pub use ns::DnsTypeNS;
pub use opt::DNSTypeOpt;
pub use soa::DnsTypeSOA;
use crate::meta::DNSType;
use std::str::FromStr;

// for wireframe convert
pub trait DNSWireFrame: Debug {
    fn decode(data: &[u8], _: Option<&[u8]>) -> Result<Self, DNSProtoErr> where Self:Sized;
    fn encode(
        &self,
        // frame: &mut Cursor<Vec<u8>>,
        compression: Option<(&mut HashMap<String, usize>, usize)>,
    ) -> Result<Vec<u8>, DNSProtoErr>;
}


pub fn decode_message_data<'a>(data: &'a [u8], original: &'a [u8], dtype: DNSType) -> Result<Box<dyn DNSWireFrame>, DNSProtoErr>{
    match dtype{
        DNSType::A => {
            match DnsTypeA::decode(data, None){
                Ok(v) => Ok(Box::new(v)),
                _ => Err(DNSProtoErr::PacketParseError),
            }
        },
        DNSType::NS => {
            match DnsTypeNS::decode(data, Some(original)){
                Ok(v) => Ok(Box::new(v)),
                _ => Err(DNSProtoErr::PacketParseError),
            }
        },
        DNSType::SOA => {
            match DnsTypeSOA::decode(data, Some(original)){
                Ok(v) => Ok(Box::new(v)),
                _ => Err(DNSProtoErr::PacketParseError),
            }
        },
        DNSType::AAAA => {
            match DnsTypeAAAA::decode(data, Some(original)){
                Ok(v) => Ok(Box::new(v)),
                _ => Err(DNSProtoErr::PacketParseError),
            }
        },
        DNSType::OPT => {
            match DNSTypeOpt::decode(data, None){
                Ok(v) => Ok(Box::new(v)),
                _ => Err(DNSProtoErr::PacketParseError),
            }
        }
        _ => {
            Err(DNSProtoErr::UnImplementedError)
        }
    }
}

pub fn decode_dns_data_from_string<'a>(string: &str, dtype: DNSType) -> Result<Box<dyn DNSWireFrame>, DNSProtoErr>{
    match dtype{
        DNSType::A => {
            match DnsTypeA::from_str(string){
                Ok(v) => Ok(Box::new(v)),
                _ => Err(DNSProtoErr::PacketParseError),
            }
        },
        _ => {
            Err(DNSProtoErr::UnImplementedError)
        }
    }
}