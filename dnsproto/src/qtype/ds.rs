use crate::meta::DNSType;
use crate::qtype::helper::{hex_u8_to_string, string_to_hex_u8};
use crate::qtype::{CompressionType, DNSWireFrame};
use nom::character::complete::{digit1, multispace0};
use nom::number::complete::{be_u16, be_u8};
use otterlib::errors::{DNSProtoErr, ParseZoneDataErr};
use std::any::Any;
use std::str::FromStr;
use std::{fmt, fmt::Formatter};

// https://tools.ietf.org/html/rfc4034#section-5.1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           Key Tag             |  Algorithm    |  Digest Type  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// /                                                               /
// /                            Digest                             /
// /                                                               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug, PartialEq)]
pub struct DnsTypeDS {
    key_tag: u16,
    algorithm_type: AlgorithemType,
    digest_type: DigestType,
    digest: Vec<u8>,
}
#[derive(Debug, Copy, Clone, PartialEq, IntoPrimitive)]
#[repr(u8)]
pub enum AlgorithemType {
    RSAMD5 = 1,
    DH = 2,
    DSA = 3,
    RSASHA1 = 5,
    DSANSEC3SHA1 = 6,
    RSASHA1NSEC3SHA1 = 7,
    RSASHA256 = 8,
    RSASHA512 = 10,
    GOST = 12,
    ECDSACurveP256SHA256 = 13,
    ECDSACurveP384SHA384 = 14,
    Ed25519 = 15,
    Ed448 = 16,
    INDIRECT = 252,
    PRIVATEDNS = 253,
    PRIVATEOID = 254,
    Unknown = 255,
}
impl AlgorithemType {
    pub fn from_u8(dt: u8) -> AlgorithemType {
        match dt {
            1 => AlgorithemType::RSAMD5,
            2 => AlgorithemType::DH,
            3 => AlgorithemType::DSA,
            5 => AlgorithemType::RSASHA1,
            6 => AlgorithemType::DSANSEC3SHA1,
            7 => AlgorithemType::DSA,
            8 => AlgorithemType::RSASHA256,
            10 => AlgorithemType::RSASHA512,
            12 => AlgorithemType::GOST,
            13 => AlgorithemType::ECDSACurveP256SHA256,
            14 => AlgorithemType::ECDSACurveP384SHA384,
            15 => AlgorithemType::Ed25519,
            16 => AlgorithemType::Ed448,
            252 => AlgorithemType::INDIRECT,
            253 => AlgorithemType::PRIVATEDNS,
            254 => AlgorithemType::PRIVATEOID,
            _ => AlgorithemType::Unknown,
        }
    }
}

impl fmt::Display for AlgorithemType {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{:?}", self)
    }
}
#[derive(Debug, Copy, Clone, PartialEq, IntoPrimitive)]
#[repr(u8)]
pub enum DigestType {
    Reserved = 0,
    SHA1 = 1,
    SHA256 = 2,
    GOST = 3,
    SHA384 = 4,
    Unknown = 255,
}

impl DigestType {
    pub fn from_u8(dt: u8) -> DigestType {
        match dt {
            1 => DigestType::SHA1,
            2 => DigestType::SHA256,
            3 => DigestType::GOST,
            4 => DigestType::SHA384,
            _ => DigestType::Unknown,
        }
    }
}
impl fmt::Display for DigestType {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{:?}", self)
    }
}
named_args!(parse_ds<'a>(size: usize)<DnsTypeDS>,
    do_parse!(
        key_tag: be_u16>>
        algorithm_type: be_u8>>
        digest_type: be_u8>>
        digest: take!(size - 4)>>
        ( DnsTypeDS::new_from_raw(
            key_tag,
            algorithm_type,
            digest_type,
            digest)
            )

    )
);

impl DnsTypeDS {
    pub fn new(
        key_tag: u16,
        algorithm_type: AlgorithemType,
        digest_type: DigestType,
        digest: String,
    ) -> Result<Self, ParseZoneDataErr> {
        Ok(DnsTypeDS {
            key_tag,
            algorithm_type,
            digest_type,
            digest: string_to_hex_u8(digest.as_str())?,
        })
    }
    pub fn new_from_raw(key_tag: u16, algorithm_type: u8, digest_type: u8, digest: &[u8]) -> Self {
        DnsTypeDS {
            key_tag,
            algorithm_type: AlgorithemType::from_u8(algorithm_type),
            digest_type: DigestType::from_u8(digest_type),
            digest: digest.to_vec(),
        }
    }

    // example : "1657 8 2 9D6BAE62219231C99FAA479716B6E4619330CE8206670AEA6C1673A055DC3AF2"
    pub fn from_str(str: &str) -> Result<Self, ParseZoneDataErr> {
        let (rest, key_tag) = digit1(str)?;
        let key_tag = u16::from_str(key_tag)?;
        let (rest, _) = multispace0(rest)?;
        let (rest, algorithm_type) = digit1(rest)?;
        let algorithm_type = u8::from_str(algorithm_type)?;
        let (rest, _) = multispace0(rest)?;
        let (rest, digest_type) = digit1(rest)?;
        let digest_type = u8::from_str(digest_type)?;
        let (digest, _) = multispace0(rest)?;
        Ok(DnsTypeDS::new_from_raw(
            key_tag,
            algorithm_type,
            digest_type,
            string_to_hex_u8(digest)?.as_slice(),
        ))
    }
}

impl fmt::Display for DnsTypeDS {
    fn fmt(&self, format: &mut Formatter<'_>) -> fmt::Result {
        write!(
            format,
            "{} {} {} {}",
            self.key_tag,
            self.algorithm_type as u8,
            self.digest_type as u8,
            hex_u8_to_string(self.digest.as_slice())
        )
    }
}
impl DNSWireFrame for DnsTypeDS {
    fn decode(data: &[u8], _: Option<&[u8]>) -> Result<Self, DNSProtoErr> {
        match parse_ds(data, data.len()) {
            Ok((_, mx)) => Ok(mx),
            Err(_err) => Err(DNSProtoErr::PacketParseError),
        }
    }

    fn get_type(&self) -> DNSType {
        DNSType::DS
    }

    fn encode(&self, _: CompressionType) -> Result<Vec<u8>, DNSProtoErr> {
        let mut data = vec![];
        data.extend_from_slice(&self.key_tag.to_be_bytes()[..]);
        data.push(self.algorithm_type.into());
        data.push(self.digest_type.into());
        data.extend_from_slice(&self.digest.as_slice());
        Ok(data)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod test {
    use crate::qtype::ds::{AlgorithemType, DigestType, DnsTypeDS};
    use crate::qtype::DNSWireFrame;
    use otterlib::errors::ParseZoneDataErr;

    fn get_example_ds() -> (&'static str, Result<DnsTypeDS, ParseZoneDataErr>) {
        let ds_str = "30909 8 2 E2D3C916F6DEEAC73294E8268FB5885044A833FC5459588F4A9184CFC41A5766";
        let ds_struct = DnsTypeDS::new(
            30909,
            AlgorithemType::RSASHA256,
            DigestType::SHA256,
            "E2D3C916F6DEEAC73294E8268FB5885044A833FC5459588F4A9184CFC41A5766".to_owned(),
        );
        (ds_str, ds_struct)
    }

    #[test]
    fn dns_ds_from_str() {
        let (ds_str, ds_struct) = get_example_ds();
        if ds_struct.is_err() {
            assert!(false, "ds new method got a unexpected failure");
            return;
        }
        let ds_struct = ds_struct.unwrap();
        match DnsTypeDS::from_str(ds_str) {
            Ok(ds) => {
                assert_eq!(ds, ds_struct);
                assert_eq!(ds_str.to_owned(), ds_str.to_string())
            }
            Err(err) => assert!(
                false,
                format!("ds from_str method got a unexpected failure: {:?}", err)
            ),
        }
    }

    #[test]
    fn ds_binary_serialize() {
        let (ds_str, ds_struct) = get_example_ds();
        let ds_struct = ds_struct.unwrap();
        let bin_arr = [
            0x78, 0xbd, 0x08, 0x02, 0xe2, 0xd3, 0xc9, 0x16, 0xf6, 0xde, 0xea, 0xc7, 0x32, 0x94,
            0xe8, 0x26, 0x8f, 0xb5, 0x88, 0x50, 0x44, 0xa8, 0x33, 0xfc, 0x54, 0x59, 0x58, 0x8f,
            0x4a, 0x91, 0x84, 0xcf, 0xc4, 0x1a, 0x57, 0x66,
        ];
        assert_eq!(DnsTypeDS::decode(&bin_arr, None).unwrap(), ds_struct);
        match ds_struct.encode(None) {
            Ok(ds_vec) => {
                assert_eq!(ds_vec.as_slice(), &bin_arr[..]);
            }
            _ => assert!(false, "encode ds fail"),
        }
        assert_eq!(ds_str, ds_struct.to_string());
    }
}
