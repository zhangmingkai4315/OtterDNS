use crate::dnsname::{parse_name, DNSName};
use crate::errors::DNSProtoErr;
use crate::types::DNSWireFrame;
use nom::lib::std::collections::HashMap;

#[derive(Debug, PartialEq)]
pub struct DnsTypeNS {
    pub(crate) ns: DNSName,
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
    fn encode(
        &self,
        _original: Option<(&mut HashMap<String, usize>, usize)>,
    ) -> Result<Vec<u8>, DNSProtoErr> {
        Err(DNSProtoErr::UnImplementedError)
    }
}

impl DnsTypeNS {
    fn decode(data: &[u8], original: Option<&[u8]>) -> Result<Self, DNSProtoErr>
    where
        Self: Sized,
    {
        match parse_ns(data, original.unwrap_or(&[])) {
            Ok((_, ns)) => Ok(ns),
            Err(_err) => Err(DNSProtoErr::PacketParseError),
        }
    }
}
