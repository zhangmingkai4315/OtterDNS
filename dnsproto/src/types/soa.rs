use crate::errors::DNSProtoErr;
use crate::types::DNSWireFrame;
use crate::message::{parse_name, DNSName};
use nom::number::complete::{be_u32};
#[derive(Debug, PartialEq)]
pub struct DnsTypeSOA {
    m_name: DNSName,
    r_name: DNSName,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32,
}

named_args!(parse_soa<'a>(original: &[u8])<DnsTypeSOA>,
    do_parse!(
        m_name: call!(parse_name, original)>>
        r_name: call!(parse_name, original) >>
        serial: be_u32>>
        refresh: be_u32>>
        retry: be_u32>>
        expire: be_u32>>
        minimum: be_u32>>
        (DnsTypeSOA{
            m_name,
            r_name,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        }
    )
));

impl DNSWireFrame for DnsTypeSOA {
    type Item = Self;
    fn decode(data: &[u8],original: Option<&[u8]>) -> Result<Self::Item, DNSProtoErr> {
        match parse_soa(data, original.unwrap_or(&[])){
            Ok((_, soa)) => Ok(soa),
            Err(_err) => Err(DNSProtoErr::PacketParseError),
        }
    }

    fn encode(&self, _original: Option<&[u8]>) -> Result<Vec<u8>, DNSProtoErr> {
        Err(DNSProtoErr::UnImplementedError)
    }
}



//
// impl FromStr for DnsTypeSOA {
//     type Err = ParseRRErr;
//     fn from_str(s: &str) -> Result<Self, Self::Err> {
//         // localhost. root.localhost. 1999010100 ( 10800 900 604800 86400 )
//         match s.parse::<Ipv4Addr>() {
//             Ok(v) => Ok(DnsTypeA(v)),
//             Err(e) => Err(ParseRRErr::from(e)),
//         }
//     }
// }
//
// impl fmt::Display for DnsTypeSOA {
//     fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
//         write!(f, "{}", self.m_name)
//     }
// }

// impl FromStr for DnsTypeSOA {
//     type Err = ParseRRErr;
//     fn from_str(s: &str) -> Result<Self, Self::Err> {
//         // localhost. root.localhost. 1999010100 ( 10800 900 604800 86400 )
//         let s1 = s.replace("(", " ").replace(")", " ");
//         let mut token = s1.split_whitespace();
//         let domain: DomainName;
//         if let Some(v) = token.next(){
//             match  v.parse::<DomainName>(){
//                 Ok(dn)=> domain = dn,
//                 Err(e) => return Err(e),
//             }
//         }
//
//     }
// }
