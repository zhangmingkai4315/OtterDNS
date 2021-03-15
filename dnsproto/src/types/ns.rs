use crate::errors::DNSProtoErr;
use crate::message::{parse_name, DNSName};
use crate::types::DNSWireFrame;
use nom::lib::std::collections::HashMap;

#[derive(Debug, PartialEq)]
pub struct DnsTypeNS {
    ns: DNSName,
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
    type Item = Self;
    fn decode(data: &[u8], original: Option<&[u8]>) -> Result<Self::Item, DNSProtoErr> {
        match parse_ns(data, original.unwrap_or(&[])) {
            Ok((_, ns)) => Ok(ns),
            Err(_err) => Err(DNSProtoErr::PacketParseError),
        }
    }

    fn encode(
        &self,
        _original: Option<(&mut HashMap<String, usize>, usize)>,
    ) -> Result<Vec<u8>, DNSProtoErr> {
        Err(DNSProtoErr::UnImplementedError)
    }
}
