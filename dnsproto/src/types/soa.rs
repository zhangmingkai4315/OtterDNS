use crate::label::DomainName;
// use crate::dns::errors::{PacketProcessErr, ParseRRErr};
// use super::BinaryConverter;
// use std::str::FromStr;
// use std::{fmt, fmt::Formatter};

// https://tools.ietf.org/html/rfc1035#section-3.3.13
//
// 3.3.13 SOA RDATA format
//
#[derive(Debug, PartialOrd, PartialEq)]
pub struct DnsTypeSOA {
    m_name: DomainName,
    r_name: DomainName,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32,
}

// impl BinaryConverter for DnsTypeSOA {
//     type Err = PacketProcessErr;
//     fn decode(data: &[u8]) -> Result<DnsTypeSOA, PacketProcessErr> {
//         if data.len() < 4 {
//             return Err(PacketProcessErr::PacketParseError);
//         }
//         return Ok(D(Ipv4Addr::from(*data)));
//     }
//     fn encode(&self) -> Result<Vec<u8>, Self::Err> {
//         Ok(self.0.octets().to_vec())
//     }
// }
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
