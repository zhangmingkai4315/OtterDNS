// http://www.networksorcery.com/enp/protocol/dns.htm
use crate::dnsname::DNSName;
use crate::label::Label;
use crate::meta::DNSType;
use crate::qtype::DNSWireFrame;
use byteorder::{BigEndian, WriteBytesExt};
use nom::lib::std::collections::HashMap;
use otterlib::errors::DNSProtoErr;
use std::io::{Cursor, Write};

#[derive(Debug)]
pub struct EDNS {
    pub(crate) name: DNSName,
    pub(crate) qtype: DNSType,
    pub(crate) payload_size: u16,
    pub(crate) extension: u8,
    pub(crate) version: u8,
    pub(crate) do_bit: bool,
    pub(crate) raw_data: Option<Vec<u8>>,
    pub(crate) data: Option<Box<dyn DNSWireFrame>>,
}
impl Default for EDNS {
    fn default() -> Self {
        EDNS::new()
    }
}

impl EDNS {
    pub fn new() -> Self {
        EDNS {
            name: DNSName::new(".", None).unwrap(),
            qtype: DNSType::OPT,
            payload_size: 1243,
            extension: 0,
            version: 0,
            do_bit: false,
            raw_data: None,
            data: None,
        }
    }
    pub fn set_dnssec_enable(&mut self, status: bool) {
        self.do_bit = status
    }
    pub fn set_payload_size(&mut self, size: u16) {
        self.payload_size = size
    }

    pub fn encode<'a>(
        &self,
        cursor: &'a mut Cursor<Vec<u8>>,
        _compression: Option<&mut HashMap<Vec<Label>, usize>>,
    ) -> Result<&'a mut Cursor<Vec<u8>>, DNSProtoErr> {
        cursor.write_u8(0)?; // root
        cursor.write_u16::<BigEndian>(self.qtype as u16)?;
        cursor.write_u16::<BigEndian>(self.payload_size)?;
        cursor.write_u8(self.extension)?;
        cursor.write_u8(self.version)?;
        cursor.write_u16::<BigEndian>((self.do_bit as u16) << 15)?;
        if self.data.is_none() {
            cursor.write_u16::<BigEndian>(0)?;
            Ok(cursor)
        } else {
            match self.data.as_ref().unwrap().encode(None) {
                Ok(encoded) => {
                    let data_length = encoded.len();
                    cursor.write_u16::<BigEndian>(data_length as u16)?;
                    cursor.write_all(encoded.as_slice())?;
                    Ok(cursor)
                }
                _ => Err(DNSProtoErr::PacketSerializeError),
            }
        }
    }

    pub fn set_rdata(&mut self, rdata: &[u8]) {
        self.raw_data = Some(rdata.to_vec());
    }
}

impl PartialEq for EDNS {
    fn eq(&self, other: &Self) -> bool {
        (self.name == other.name)
            && (self.qtype == other.qtype)
            && (self.extension == other.extension)
            && (self.do_bit == other.do_bit)
            && (self.payload_size == other.payload_size)
            && (self.raw_data == other.raw_data)
    }
}
