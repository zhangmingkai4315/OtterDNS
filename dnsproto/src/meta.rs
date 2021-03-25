// http://www.networksorcery.com/enp/protocol/dns.htm
use crate::dnsname::DNSName;
use crate::errors::DNSProtoErr;
use crate::qtype::DNSWireFrame;
use byteorder::{BigEndian, WriteBytesExt};
use nom::lib::std::collections::HashMap;
use rand::Rng;
use std::io::{Cursor, Write};

// https://tools.ietf.org/html/rfc1035
// 1  1  1  1  1  1
// 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                      ID                       |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    QDCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    ANCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    NSCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    ARCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

#[derive(Debug, PartialEq, Eq)]
pub struct Header {
    pub(crate) id: u16,
    pub(crate) qr: bool,
    pub(crate) op_code: OpCode,
    pub(crate) aa: bool,
    pub(crate) tc: bool,
    pub(crate) rd: bool,
    pub(crate) ra: bool,
    pub(crate) z: bool,
    pub(crate) ad: bool,
    pub(crate) cd: bool,
    pub(crate) r_code: RCode,
    pub(crate) question_count: u16,
    pub(crate) answer_count: u16,
    pub(crate) ns_count: u16,
    pub(crate) additional_count: u16,
}
impl Header {
    pub fn new() -> Header {
        let mut rng = rand::thread_rng();
        Header {
            id: rng.gen::<u16>(),
            qr: false,
            op_code: OpCode::Query,
            aa: false,
            tc: false,
            rd: false,
            ra: false,
            z: false,
            ad: false,
            cd: false,
            r_code: RCode::NoError,
            question_count: 0,
            answer_count: 0,
            ns_count: 0,
            additional_count: 0,
        }
    }
    pub fn set_id(&mut self, id: u16) {
        self.id = id
    }
    pub fn set_rd(&mut self, rd: bool) {
        self.rd = rd;
    }
    pub fn set_qr(&mut self, qr: bool) {
        self.qr = qr;
    }
    pub fn set_random_id(&mut self) -> u16 {
        let mut rng = rand::thread_rng();
        let id = rng.gen::<u16>();
        self.id = id;
        id
    }
    pub fn encode<'a>(
        &self,
        cursor: &'a mut Cursor<Vec<u8>>,
    ) -> Result<&'a mut Cursor<Vec<u8>>, DNSProtoErr> {
        // if wireframe.len() <= 12 {
        //     wireframe.resize(12, 0);
        // }
        // let mut cursor = Cursor::new(wireframe);

        cursor.write_u16::<BigEndian>(self.id)?;
        let mut h0 = (self.qr as u8) << 7;
        let opcode: u8 = self.op_code.into();
        h0 |= (opcode) << 3;
        h0 |= (self.aa as u8) << 2;
        h0 |= (self.aa as u8) << 1;
        h0 |= self.rd as u8;

        let mut h1 = (self.ra as u8) << 7;
        let rcode: u8 = self.r_code.into();
        h1 |= (self.z as u8) << 6;
        h1 |= rcode;
        cursor.write_u8(h0)?;
        cursor.write_u8(h1)?;
        cursor.write_u16::<BigEndian>(self.question_count)?;
        cursor.write_u16::<BigEndian>(self.answer_count)?;
        cursor.write_u16::<BigEndian>(self.ns_count)?;
        cursor.write_u16::<BigEndian>(self.additional_count)?;
        Ok(cursor)
    }
}
impl Default for Header {
    fn default() -> Self {
        Header::new()
    }
}

// 1  1  1  1  1  1
// 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                                               |
// /                     QNAME                     /
// /                                               /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                     QTYPE                     |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                     QCLASS                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

#[derive(Debug, PartialEq)]
pub struct Question {
    pub(crate) q_name: DNSName,
    pub(crate) q_type: DNSType,
    pub(crate) q_class: DNSClass,
}

impl Question {
    pub fn new(domain: &str, q_type: DNSType, q_class: DNSClass) -> Result<Question, DNSProtoErr> {
        Ok(Question {
            q_name: DNSName::new(domain)?,
            q_type,
            q_class,
        })
    }
    pub fn encode<'a>(
        &self,
        cursor: &'a mut Cursor<Vec<u8>>,
        compression: Option<&mut HashMap<String, usize>>,
    ) -> Result<&'a mut Cursor<Vec<u8>>, DNSProtoErr> {
        let frame = {
            match compression {
                None => self.q_name.to_binary(None),
                Some(compression) => self
                    .q_name
                    .to_binary(Some((compression, cursor.position() as usize))),
            }
            // if compression.is_none() {
            //     self.q_name.to_binary(None)
            // } else {
            //     self.q_name
            //         .to_binary(Some((compression.unwrap(), cursor.position() as usize)))
            // }
        };
        cursor.write_all(frame.as_slice())?;
        cursor.write_u16::<BigEndian>(self.q_type as u16)?;
        cursor.write_u16::<BigEndian>(self.q_class as u16)?;
        Ok(cursor)
    }
}

// 1  1  1  1  1  1
// 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                                               |
// /                                               /
// /                      NAME                     /
// |                                               |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                      TYPE                     |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                     CLASS                     |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                      TTL                      |
// |                                               |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                   RDLENGTH                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
// /                     RDATA                     /
// /                                               /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#[derive(Debug)]
pub struct ResourceRecord {
    pub(crate) name: DNSName,
    pub(crate) qtype: DNSType,
    pub(crate) qclass: DNSClass,
    pub(crate) ttl: u32,
    pub(crate) data: Option<Box<dyn DNSWireFrame>>,
}

impl PartialEq for ResourceRecord {
    fn eq(&self, other: &Self) -> bool {
        (self.name == other.name)
            && (self.qtype == other.qtype)
            && (self.qclass == other.qclass)
            && (self.ttl == other.ttl)
        // && (self.raw_data == other.raw_data)
    }
}

impl ResourceRecord {
    pub fn new(
        domain: &str,
        qtype: DNSType,
        qclass: DNSClass,
        ttl: u32,
        data: Option<Box<dyn DNSWireFrame>>,
    ) -> Result<ResourceRecord, DNSProtoErr> {
        Ok(ResourceRecord {
            name: DNSName::new(domain)?,
            qtype,
            qclass,
            ttl,
            data,
        })
    }
    #[inline]
    pub fn get_type(&self) -> DNSType {
        self.qtype
    }

    pub fn get_label_count(&self) -> usize {
        self.name.label_count()
    }
    pub fn get_dname(&self) -> &DNSName {
        &self.name
    }
    pub fn get_label_iter(&self) -> Iter<'_, Label> {
        self.name.labels.iter()
    }
    pub fn encode<'a>(
        &self,
        cursor: &'a mut Cursor<Vec<u8>>,
        compression: Option<&mut HashMap<String, usize>>,
    ) -> Result<&'a mut Cursor<Vec<u8>>, DNSProtoErr> {
        let offset = cursor.position();
        if self.data.is_none() {
            return Err(DNSProtoErr::PacketSerializeError);
        }
        let (frame, compression) = match compression {
            Some(cp) => (self.name.to_binary(Some((cp, offset as usize))), Some(cp)),
            _ => (self.name.to_binary(None), None),
        };
        cursor.write_all(frame.as_slice())?;
        cursor.write_u16::<BigEndian>(self.qtype as u16)?;
        cursor.write_u16::<BigEndian>(self.qclass as u16)?;
        cursor.write_u32::<BigEndian>(self.ttl)?;

        let encoded = match compression {
            Some(cp) => self
                .data
                .as_ref()
                .unwrap()
                .encode(Some((cp, cursor.position() as usize))),
            _ => self.data.as_ref().unwrap().encode(None),
        };
        if encoded.is_err() {
            return Err(DNSProtoErr::PacketSerializeError);
        }
        let data = encoded.unwrap();
        let length = data.len() as u16;
        cursor.write_u16::<BigEndian>(length)?;
        cursor.write_all(data.as_slice())?;
        Ok(cursor)
    }
}

#[derive(Debug, Default)]
pub struct RRSet {
    content: Vec<ResourceRecord>,
    signatures: Vec<ResourceRecord>,
    ttl: u32,
}

impl RRSet {
    pub fn set_ttl(&mut self, ttl: u32) {
        self.ttl = ttl;
    }
    pub fn clear(&mut self) {
        self.signatures.clear();
        self.signatures.clear();
    }
    pub fn add(&mut self, rr: ResourceRecord) {
        self.ttl = rr.ttl;
        if rr.qtype == DNSType::RRSIG {
            self.signatures.push(rr);
            return;
        }
        self.content.push(rr);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpCode {
    Query,
    IQuery,
    Status,
    Reserved,
    Notify,
    Update,
}
impl From<u8> for OpCode {
    fn from(opcode: u8) -> Self {
        match opcode {
            0 => OpCode::Query,
            1 => OpCode::IQuery,
            2 => OpCode::Status,
            3 => OpCode::Reserved,
            4 => OpCode::Notify,
            5 => OpCode::Update,
            _ => OpCode::Reserved,
        }
    }
}

impl Into<u8> for OpCode {
    fn into(self) -> u8 {
        match self {
            OpCode::Query => 0,
            OpCode::IQuery => 1,
            OpCode::Status => 2,
            OpCode::Reserved => 3,
            OpCode::Notify => 4,
            OpCode::Update => 5,
        }
    }
}

// http://www.tcpipguide.com/free/t_DNSMessageHeaderandQuestionSectionFormat.htm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RCode {
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
    YxDomain,
    YxRRSet,
    NxRRSet,
    NotAuth,
    NotZone,
    Unknown,
}

impl From<u8> for RCode {
    fn from(rcode: u8) -> Self {
        match rcode {
            0 => RCode::NoError,
            1 => RCode::FormatError,
            2 => RCode::ServerFailure,
            3 => RCode::NameError,
            4 => RCode::NotImplemented,
            5 => RCode::Refused,
            6 => RCode::YxDomain,
            7 => RCode::YxRRSet,
            8 => RCode::NxRRSet,
            9 => RCode::NotAuth,
            10 => RCode::NotZone,
            _ => RCode::Unknown,
        }
    }
}
impl Into<u8> for RCode {
    fn into(self) -> u8 {
        match self {
            RCode::NoError => 0,
            RCode::FormatError => 1,
            RCode::ServerFailure => 2,
            RCode::NameError => 3,
            RCode::NotImplemented => 4,
            RCode::Refused => 5,
            RCode::YxDomain => 6,
            RCode::YxRRSet => 7,
            RCode::NxRRSet => 8,
            RCode::NotAuth => 9,
            RCode::NotZone => 10,
            RCode::Unknown => 11,
        }
    }
}

use nom::lib::std::slice::Iter;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use crate::label::Label;

/// https://tools.ietf.org/html/rfc1035#section-3.2.4
/// specify the class of the dns record data
#[derive(Debug, PartialEq, Copy, Clone, IntoPrimitive, TryFromPrimitive)]
#[repr(u16)]
pub enum DNSClass {
    #[num_enum(default)]
    IN = 1,
    // 1 the Internet
    CS,
    // 2 the CSNET class
    CH,
    // 3 the CHAOS class
    HS, // 4 Hesiod
}

impl Default for DNSClass {
    fn default() -> Self {
        DNSClass::IN
    }
}

#[derive(Debug, PartialEq, Copy, Clone, IntoPrimitive, FromPrimitive, Eq, Hash)]
#[repr(u16)]
#[derive(EnumString)]
pub enum DNSType {
    #[num_enum(default)]
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    HINFO = 13,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    OPT = 41,
    DS = 43,
    RRSIG = 46,
    NSEC = 47,
    DNSKEY = 48,
    NSEC3 = 50,
    NSEC3PARAM = 51,
    AXFR = 252,
    Any = 255, // Rfc1035: return all records of all types known to the dns server
}

impl Default for DNSType {
    fn default() -> Self {
        DNSType::A
    }
}
