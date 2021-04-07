use crate::meta::DNSType;
use crate::qtype::{CompressionType, DNSWireFrame};
use nom::character::complete::{digit1, multispace0};
use nom::number::complete::{be_u16, be_u8};
use otterlib::errors::OtterError::DNSProtoError;
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
    digest: String,
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
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
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
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
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
            digest,
        })
    }
    pub fn new_from_raw(key_tag: u16, algorithm_type: u8, digest_type: u8, digest: &[u8]) -> Self {
        let digest_string = {
            match std::str::from_utf8(digest) {
                Ok(digtest_val) => digtest_val.to_owned(),
                _ => "".to_owned(),
            }
        };
        DnsTypeDS {
            key_tag,
            algorithm_type: AlgorithemType::from_u8(algorithm_type),
            digest_type: DigestType::from_u8(digest_type),
            digest: digest_string,
        }
    }

    // example : "1657 8 2 9D6BAE62219231C99FAA479716B6E4619330CE8206670AEA6C1673A055DC3AF2"
    pub fn from_str(str: &str, _: Option<&str>) -> Result<Self, ParseZoneDataErr> {
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
            digest.as_bytes(),
        ))
    }
}

impl fmt::Display for DnsTypeDS {
    fn fmt(&self, format: &mut Formatter<'_>) -> fmt::Result {
        write!(
            format,
            "{:?} {} {} {}",
            self.key_tag,
            self.algorithm_type.to_string(),
            self.digest_type.to_string(),
            &self.digest
        )
    }
}
impl DNSWireFrame for DnsTypeDS {
    fn decode(data: &[u8], _: Option<&[u8]>) -> Result<Self, DNSProtoErr> {
        match parse_ds(data, data.len()) {
            Ok((_, mx)) => Ok(mx),
            Err(_err) => return Err(DNSProtoErr::PacketParseError),
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
        data.extend_from_slice(&self.digest.as_bytes());
        Ok(data)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod test {
    use crate::label::Label;
    use crate::qtype::{DNSWireFrame, DnsTypeMX};
    use std::collections::HashMap;
    use std::str::FromStr;

    #[test]
    fn test_dns_type_ds() {
        // let bin_arr = [
        //     0x00u8, 0x0f, 0x02, 0x6d, 0x78, 0x01, 0x6e, 0x06, 0x73, 0x68, 0x69, 0x66, 0x65, 0x6e,
        //     0x03, 0x63, 0x6f, 0x6d, 0x00,
        // ];
        // assert_eq!(
        //     DnsTypeMX::decode(&bin_arr, None).unwrap(),
        //     DnsTypeMX::new(15, "mx.n.shifen.com.").unwrap()
        // );
        //
        // assert_eq!(
        //     DnsTypeMX::from_str("15 mx.n.shifen.com.", None).unwrap(),
        //     DnsTypeMX::new(15, "mx.n.shifen.com.").unwrap()
        // );
        //
        // assert_eq!(
        //     DnsTypeMX::from_str("15 mx.n.shifen.com.", None)
        //         .unwrap()
        //         .encode(None)
        //         .unwrap(),
        //     &bin_arr,
        // );
        // let mut compression_map = HashMap::new();
        // compression_map.insert(vec![Label::from_str("com").unwrap()], 12usize);
        // let compressed_bin = [
        //     0x00u8, 0x0f, 0x02, 0x6d, 0x78, 0x01, 0x6e, 0x06, 0x73, 0x68, 0x69, 0x66, 0x65, 0x6e,
        //     0xc0, 0x0c,
        // ];
        // assert_eq!(
        //     DnsTypeMX::from_str("15 mx.n.shifen.com.", None)
        //         .unwrap()
        //         .encode(Some((&mut compression_map, 0)))
        //         .unwrap(),
        //     &compressed_bin,
        // );
    }
}
