// http://www.networksorcery.com/enp/protocol/dns.htm
use crate::dnsname::DNSName;
use crate::errors::DNSProtoErr;
use crate::meta::DNSType;
use crate::qtype::DNSWireFrame;
use byteorder::{BigEndian, WriteBytesExt};
use nom::lib::std::collections::HashMap;
use std::io::{Cursor, Write};

#[derive(Debug)]
pub struct EDNS {
    pub(crate) name: DNSName,
    pub(crate) qtype: DNSType,
    pub(crate) payload_size: u16,
    pub(crate) extension: u8,
    pub(crate) version: u8,
    pub(crate) do_bit: bool,
    pub(crate) raw_data: Vec<u8>,
    pub(crate) data: Option<Box<dyn DNSWireFrame>>,
}

impl EDNS {
    pub fn encode(
        &mut self,
        wireframe: &mut Vec<u8>,
        offset: usize,
        _compression: Option<&mut HashMap<String, usize>>,
    ) -> Result<usize, DNSProtoErr> {
        // let (_, right) = wireframe.split_at_mut(offset);
        let mut cursor = Cursor::new(wireframe);
        cursor.set_position(offset as u64);
        let header_length = offset + 10;
        cursor.write_u8(0)?; // root
        cursor.write_u16::<BigEndian>(self.qtype as u16)?;
        cursor.write_u16::<BigEndian>(self.payload_size)?;
        cursor.write_u8(self.extension)?;
        cursor.write_u8(self.version)?;
        cursor.write_u16::<BigEndian>((self.do_bit as u16) << 15)?;
        if self.data.is_none() {
            cursor.write_u16::<BigEndian>(0)?;
            Ok(header_length)
        } else {
            match self.data.as_ref().unwrap().encode(None) {
                Ok(encoded) => {
                    let data_length = encoded.len();
                    cursor.write_u16::<BigEndian>(0)?;
                    cursor.write_all(encoded.as_slice())?;
                    Ok(header_length + data_length)
                }
                _ => Err(DNSProtoErr::PacketSerializeError),
            }
        }
    }

    pub fn set_rdata(&mut self, rdata: &[u8]) {
        self.raw_data = rdata.to_vec();
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
