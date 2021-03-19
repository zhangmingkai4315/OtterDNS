use crate::dnsname::{parse_name, DNSName};
use crate::errors::DNSProtoErr;
use crate::qtype::DNSWireFrame;
use nom::number::complete::be_u32;
use std::collections::HashMap;

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

impl DnsTypeSOA {
    pub(crate) fn decode(data: &[u8], original: Option<&[u8]>) -> Result<Self, DNSProtoErr> {
        match parse_soa(data, original.unwrap_or(&[])) {
            Ok((_, soa)) => Ok(soa),
            Err(_err) => Err(DNSProtoErr::PacketParseError),
        }
    }
}

impl DNSWireFrame for DnsTypeSOA {
    fn encode(
        &self,
        compression: Option<(&mut HashMap<String, usize>, usize)>,
    ) -> Result<Vec<u8>, DNSProtoErr>  where Self:Sized{
        let mut data = vec![];
        match compression {
            Some((compression_map, size)) => {
                let m_name = self.m_name.to_binary(Some((compression_map, size)));
                data.extend_from_slice(m_name.as_slice());
                let r_name = self
                    .r_name
                    .to_binary(Some((compression_map, size + m_name.len())));
                data.extend_from_slice(r_name.as_slice());
            }
            _ => {
                let m_name = self.m_name.to_binary(None);
                data.extend_from_slice(m_name.as_slice());
                let r_name = self.r_name.to_binary(None);
                data.extend_from_slice(r_name.as_slice());
            }
        }
        data.extend_from_slice(&self.serial.to_be_bytes()[..]);
        data.extend_from_slice(&self.refresh.to_be_bytes()[..]);
        data.extend_from_slice(&self.retry.to_be_bytes()[..]);
        data.extend_from_slice(&self.expire.to_be_bytes()[..]);
        data.extend_from_slice(&self.minimum.to_be_bytes()[..]);
        Ok(data)
    }
    fn decode(data: &[u8], original: Option<&[u8]>) -> Result<Self, DNSProtoErr> {
        match parse_soa(data, original.unwrap_or(&[])) {
            Ok((_, soa)) => Ok(soa),
            Err(_err) => Err(DNSProtoErr::PacketParseError),
        }
    }
}

#[test]
fn test_soa_encode() {
    let non_compression_vec: Vec<u8> = vec![
        1, 97, 12, 103, 116, 108, 100, 45, 115, 101, 114, 118, 101, 114, 115, 3, 110, 101, 116, 0,
        5, 110, 115, 116, 108, 100, 12, 118, 101, 114, 105, 115, 105, 103, 110, 45, 103, 114, 115,
        3, 99, 111, 109, 0, 96, 79, 29, 111, 0, 0, 7, 8, 0, 0, 3, 132, 0, 9, 58, 128, 0, 1, 81,
        128,
    ];
    let compression_vec: Vec<u8> = vec![
        1, 97, 12, 103, 116, 108, 100, 45, 115, 101, 114, 118, 101, 114, 115, 3, 110, 101, 116, 0,
        5, 110, 115, 116, 108, 100, 12, 118, 101, 114, 105, 115, 105, 103, 110, 45, 103, 114, 115,
        0xc0, 0x0c, 96, 79, 29, 111, 0, 0, 7, 8, 0, 0, 3, 132, 0, 9, 58, 128, 0, 1, 81, 128,
    ];
    let soa = DnsTypeSOA {
        m_name: DNSName::new("a.gtld-servers.net.").unwrap(),
        r_name: DNSName::new("nstld.verisign-grs.com.").unwrap(),
        serial: 1615797615,
        refresh: 1800,
        retry: 900,
        expire: 604800,
        minimum: 86400,
    };
    match soa.encode(None) {
        Ok(v) => {
            println!("{:x?}", v);
            assert_eq!(v, non_compression_vec, "soa encode not equal")
        }
        Err(err) => {
            assert!(false, format!("error: {:?}", err));
        }
    }
    let mut compression_map = HashMap::new();
    compression_map.insert("com".to_owned(), 12);
    match soa.encode(Some((&mut compression_map, 0))) {
        Ok(v) => {
            // println!("{:x?}", v);
            assert_eq!(v, compression_vec, "soa encode not equal")
        }
        Err(err) => {
            assert!(false, format!("error: {:?}", err));
        }
    }
}
