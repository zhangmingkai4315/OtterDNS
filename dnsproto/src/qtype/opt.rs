use crate::errors::DNSProtoErr;
use crate::qtype::DNSWireFrame;
use byteorder::{BigEndian, WriteBytesExt};
use nom::number::complete::{be_u16, be_u8};
use std::collections::HashMap;
use std::fmt::{self, Formatter};
use std::io::{Cursor, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
#[derive(Debug, Copy, Clone, PartialEq)]
#[repr(u16)]
pub enum EDNSOptionCode {
    Reserved = 0,
    ECS = 8,
    Cookie = 10,
}

impl From<u16> for EDNSOptionCode {
    fn from(vdata: u16) -> Self {
        match vdata {
            x1 if x1 == 8 => Self::ECS,
            x1 if x1 == 10 => Self::Cookie,
            _ => Self::Reserved,
        }
    }
}

#[derive(Debug, PartialOrd, PartialEq)]
pub struct EdnsECS {
    family: u16,
    source_mask: u8,
    scope_mask: u8,
    client_subnet: Vec<u8>,
}

impl EdnsECS {
    fn encode(&self, mut cursor: Cursor<Vec<u8>>) -> Result<(Cursor<Vec<u8>>, usize), DNSProtoErr> {
        cursor.write_u16::<BigEndian>(self.family)?;
        cursor.write_u8(self.source_mask)?;
        cursor.write_u8(self.scope_mask)?;
        cursor.write_all(self.client_subnet.as_slice())?;
        Ok((cursor, 4 + self.client_subnet.len()))
    }

    fn new_ipv6(ipaddr: Ipv6Addr, source_mask: u8, scope_mask: u8) -> Result<Self, DNSProtoErr> {
        let client_subnet = ipaddr.octets();
        let mut size = source_mask / 8;
        if source_mask % 8 != 0 {
            size += 1;
        }
        let (client_subnet, _) = client_subnet.split_at(size as usize);
        Ok(EdnsECS {
            family: { 1 },
            source_mask,
            scope_mask,
            client_subnet: client_subnet.to_vec(),
        })
    }
    fn new_ipv4(ipaddr: Ipv4Addr, source_mask: u8, scope_mask: u8) -> Result<Self, DNSProtoErr> {
        if source_mask > 32 {
            return Err(DNSProtoErr::PacketSerializeError);
        }
        let client_subnet = ipaddr.octets();
        let mut size = source_mask / 8;
        if source_mask % 8 != 0 {
            size += 1;
        }
        let (client_subnet, _) = client_subnet.split_at(size as usize);
        Ok(EdnsECS {
            family: { 1 },
            source_mask,
            scope_mask,
            client_subnet: client_subnet.to_vec(),
        })
    }
}

named_args!(parse_edns_ecs<'a>(size: u16)<EdnsECS>,
    do_parse!(
        family: be_u16>>
        source_mask: be_u8>>
        scope_mask: be_u8>>
        client_subnet: take!(size - 4)>>
        (EdnsECS{
            family,
            source_mask,
            scope_mask,
            client_subnet:client_subnet.to_vec(),
        }
    )
));

#[derive(Debug, PartialOrd, PartialEq)]
pub struct EdnsCookie {
    client_cookie: Vec<u8>,
    server_cookie: Vec<u8>,
}
impl EdnsCookie {
    fn encode(&self, mut cursor: Cursor<Vec<u8>>) -> Result<(Cursor<Vec<u8>>, usize), DNSProtoErr> {
        cursor.write_all(self.client_cookie.as_slice())?;
        cursor.write_all(self.server_cookie.as_slice())?;
        // client cookie is 8 bytes.
        Ok((cursor, 8 + self.server_cookie.len()))
    }
}

#[derive(Debug, PartialOrd, PartialEq)]
pub enum Opt {
    //
    ECS(EdnsECS),
    // https://tools.ietf.org/html/rfc7873
    Cookie(EdnsCookie),
}

#[derive(Debug, PartialEq)]
pub struct DNSTypeOpt {
    pub(crate) code: EDNSOptionCode,
    pub(crate) length: u16,
    pub(crate) raw_data: Vec<u8>,
    pub(crate) data: Option<Opt>,
}

impl fmt::Display for DNSTypeOpt {
    fn fmt(&self, _format: &mut Formatter<'_>) -> fmt::Result {
        unimplemented!()
    }
}

impl DNSWireFrame for DNSTypeOpt {
    fn decode(data: &[u8], _: Option<&[u8]>) -> Result<Self, DNSProtoErr>
    where
        Self: Sized,
    {
        match parse_opt(data) {
            Ok((_, mut opt)) => match opt.decode_with_type() {
                Ok(_) => Ok(opt),
                Err(_) => Err(DNSProtoErr::PacketParseError),
            },
            Err(_err) => Err(DNSProtoErr::PacketParseError),
        }
    }
    fn encode(
        &self,
        _: Option<(&mut HashMap<String, usize>, usize)>,
    ) -> Result<Vec<u8>, DNSProtoErr> {
        let frame = vec![];
        let mut cursor = Cursor::new(frame);
        if self.data.is_none() {
            cursor.write_u16::<BigEndian>(0)?;
            return Ok(cursor.into_inner());
        }
        if let Ok((mut cursor, size)) = {
            match self.data.as_ref().unwrap() {
                Opt::ECS(ecs) => ecs.encode(cursor),
                Opt::Cookie(cookie) => cookie.encode(cursor),
            }
        } {
            cursor.set_position(2);
            cursor.write_u16::<BigEndian>(size as u16)?;
            Ok(cursor.into_inner())
        } else {
            Err(DNSProtoErr::PacketSerializeError)
        }
    }
}

named_args!(parse_opt<'a>()<DNSTypeOpt>,
    do_parse!(
        code: be_u16>>
        length: be_u16>>
        raw_data: take!(length)>>
        (DNSTypeOpt{
            code: code.into(),
            length,
            data: None,
            raw_data: raw_data.to_vec(),
        }
    )
));

impl Default for DNSTypeOpt {
    fn default() -> Self {
        DNSTypeOpt {
            code: EDNSOptionCode::Reserved,
            length: 0,
            raw_data: vec![],
            data: None,
        }
    }
}

impl DNSTypeOpt {
    fn decode_with_type(&mut self) -> Result<(), DNSProtoErr> {
        match self.code {
            EDNSOptionCode::Reserved => Ok(()),
            EDNSOptionCode::ECS => match parse_edns_ecs(self.raw_data.as_slice(), self.length) {
                Ok((_, v2)) => {
                    self.data = Some(Opt::ECS(v2));
                    Ok(())
                }
                _ => Err(DNSProtoErr::PacketParseError),
            },
            _ => Err(DNSProtoErr::UnImplementedError),
        }
    }
}

#[test]
fn test_ecs_create() {
    match EdnsECS::new_ipv4("1.0.0.0".parse().unwrap(), 8, 0) {
        Ok(ecs) => {
            let data = Vec::new();
            let cursor = Cursor::new(data);
            match ecs.encode(cursor) {
                Ok((val, _)) => {
                    assert_eq!(val.into_inner(), vec![0, 1, 8, 0, 1]);
                }
                Err(_) => assert!(false),
            }
        }
        Err(_) => assert!(false),
    }
    match EdnsECS::new_ipv4("1.1.0.0".parse().unwrap(), 16, 0) {
        Ok(ecs) => {
            let data = Vec::new();
            let cursor = Cursor::new(data);
            match ecs.encode(cursor) {
                Ok((val, _)) => {
                    assert_eq!(val.into_inner(), vec![0, 1, 16, 0, 1, 1]);
                }
                Err(_) => assert!(false),
            }
        }
        Err(_) => assert!(false),
    }
}

// impl FromStr for DnsTypeA {
//     type Err = ParseZoneDataErr;
//     fn from_str(a_str: &str) -> Result<Self, Self::Err> {
//         match a_str.parse::<Ipv4Addr>() {
//             Ok(v4_addr) => Ok(DnsTypeA(v4_addr)),
//             Err(err) => Err(ParseZoneDataErr::AddrParseError(err)),
//         }
//     }
// }

// impl fmt::Display for DNSTypeOpt {
//     fn fmt(&self, format: &mut Formatter<'_>) -> fmt::Result {
//         write!(format, "{}", self.0.to_string())
//     }
// }
