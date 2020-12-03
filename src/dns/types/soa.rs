use crate::dns::label::DomainName;
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
