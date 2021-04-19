// 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   Hash Alg.   |     Flags     |          Iterations           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Salt Length  |                     Salt                      /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Hash Length  |             Next Hashed Owner Name            /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// /                         Type Bit Maps                         /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

use crate::meta::DNSType;
use crate::qtype::ds::DigestType;
use crate::qtype::helper::{
    encode_nsec_bitmap_from_str, encode_nsec_bitmap_from_types, hex_u8_to_string,
    nsec_bitmaps_to_string, string_to_hex_u8,
};
use crate::qtype::soa::is_not_space;
use crate::qtype::{CompressionType, DNSWireFrame};
use data_encoding::BASE32_DNSSEC;
use nom::bytes::complete::take_while;
use nom::character::complete::{digit1, multispace0};
use nom::combinator::rest;
use nom::number::complete::{be_u16, be_u8};
use otterlib::errors::DNSProtoErr;
use std::any::Any;
use std::fmt;
use std::fmt::Formatter;
use std::str::FromStr;

#[derive(Debug, PartialEq, Clone)]
pub struct DnsTypeNSEC3 {
    hash_algorithem: u8,
    flag: u8,
    iterations: u16,
    salt: Vec<u8>,
    hash: Vec<u8>,
    bitmaps: Vec<u8>,
}

fn encode_nsec3_hash_from_str(hash: &str) -> Result<Vec<u8>, DNSProtoErr> {
    match BASE32_DNSSEC.decode(hash.as_bytes()) {
        Ok(v) => Ok(v),
        Err(err) => Err(DNSProtoErr::GeneralErr(format!(
            "decode nsec3 hash fail: {:?}",
            err
        ))),
    }
}

fn decode_nsec3_hash_to_string(hash: &[u8]) -> String {
    BASE32_DNSSEC.encode(hash).to_uppercase()
}

impl DnsTypeNSEC3 {
    pub fn new_from_raw(
        hash_algorithem: DigestType,
        flag: u8,
        iterations: u16,
        salt: &str,
        hash: Vec<u8>,
        type_arr: Vec<DNSType>,
    ) -> Result<Self, DNSProtoErr> {
        Ok(DnsTypeNSEC3 {
            hash_algorithem: hash_algorithem as u8,
            flag,
            iterations,
            salt: string_to_hex_u8(salt)?,
            hash,
            bitmaps: encode_nsec_bitmap_from_types(type_arr)?,
        })
    }

    pub fn decode(data: &[u8], original: Option<&[u8]>) -> Result<Self, DNSProtoErr> {
        match parse_nsec3(data, original.unwrap_or(&[])) {
            Ok((_, nsec)) => Ok(nsec),
            Err(_err) => Err(DNSProtoErr::PacketParseError),
        }
    }

    // 1 0 5 4CD7B054F876956C 1KH27L1DSQOR2RO6I202GTCTPDHKCB93  A NS SOA MX TXT AAAA RRSIG DNSKEY NSEC3PARAM
    pub fn from_str(str: &str, _: Option<&str>) -> Result<Self, DNSProtoErr> {
        let (rest, _) = multispace0(str)?;
        let (rest, hash_algorithem) = digit1(rest)?;
        let hash_algorithem = u8::from_str(hash_algorithem)?;

        let (rest, _) = multispace0(rest)?;
        let (rest, flag) = digit1(rest)?;
        let flag = u8::from_str(flag)?;

        let (rest, _) = multispace0(rest)?;
        let (rest, iterations) = digit1(rest)?;
        let iterations = u16::from_str(iterations)?;

        let (rest, _) = multispace0(rest)?;
        let (rest, salt) = take_while(is_not_space)(rest)?;
        let (rest, _) = multispace0(rest)?;

        let (rest, _) = multispace0(rest)?;
        let (rest, hash) = take_while(is_not_space)(rest)?;
        let (rest, _) = multispace0(rest)?;
        let rest = rest.trim();
        Ok(DnsTypeNSEC3 {
            hash_algorithem,
            flag,
            iterations,
            salt: string_to_hex_u8(salt)?,
            hash: encode_nsec3_hash_from_str(hash)?,
            bitmaps: encode_nsec_bitmap_from_str(rest)?,
        })
    }
}

impl fmt::Display for DnsTypeNSEC3 {
    fn fmt(&self, format: &mut Formatter<'_>) -> fmt::Result {
        let type_str = {
            match nsec_bitmaps_to_string(self.bitmaps.as_slice()) {
                Ok(nsec_result) => nsec_result,
                Err(err) => format!("decode fail: {:?}", err),
            }
        };

        write!(
            format,
            "{} {} {} {} {} {}",
            self.hash_algorithem,
            self.flag,
            self.iterations,
            hex_u8_to_string(self.salt.as_slice()),
            decode_nsec3_hash_to_string(self.hash.as_slice()),
            type_str
        )
    }
}
impl DNSWireFrame for DnsTypeNSEC3 {
    fn get_type(&self) -> DNSType {
        DNSType::NSEC3
    }

    fn encode(&self, _: CompressionType) -> Result<Vec<u8>, DNSProtoErr> {
        let mut data = vec![];
        data.push(self.hash_algorithem);
        data.push(self.flag);
        data.extend_from_slice(&self.iterations.to_be_bytes());
        data.push(self.salt.len() as u8);
        data.extend_from_slice(self.salt.as_slice());
        data.push(self.hash.len() as u8);
        data.extend_from_slice(self.hash.as_slice());
        data.extend_from_slice(self.bitmaps.as_slice());
        Ok(data)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn clone_box(&self) -> Box<dyn DNSWireFrame> {
        Box::new(Self {
            hash_algorithem: self.hash_algorithem,
            flag: self.flag,
            iterations: self.iterations,
            salt: self.salt.clone(),
            bitmaps: self.bitmaps.clone(),
            hash: self.hash.clone(),
        })
    }
}

named_args!(parse_nsec3<'a>(original: &[u8])<DnsTypeNSEC3>,
    do_parse!(
        hash_algorithem: be_u8>>
        flag: be_u8>>
        iterations: be_u16>>
        salt_length: be_u8>>
        salt: take!(salt_length)>>
        hash_length: be_u8>>
        hash: take!(hash_length)>>
        bitmaps: call!(rest)>>
        (DnsTypeNSEC3{
            hash_algorithem,
            flag,
            iterations,
            salt: salt.to_vec(),
            hash: hash.to_vec(),
            bitmaps: bitmaps.to_vec(),
        }
    )
));

#[cfg(test)]
mod test {
    use crate::meta::DNSType;
    use crate::qtype::ds::DigestType;
    use crate::qtype::nsec3::{
        decode_nsec3_hash_to_string, encode_nsec3_hash_from_str, DnsTypeNSEC3,
    };
    use crate::qtype::DNSWireFrame;

    fn get_example_nsec3() -> (Vec<u8>, String, DnsTypeNSEC3) {
        let nsec3_str = "1 0 5 4CD7B054F876956C 1KH27L1DSQOR2RO6I202GTCTPDHKCB93 A NS SOA MX TXT AAAA RRSIG DNSKEY NSEC3PARAM";
        let nsec3_struct = DnsTypeNSEC3::new_from_raw(
            DigestType::SHA1,
            0,
            5,
            "4CD7B054F876956C",
            encode_nsec3_hash_from_str("1KH27L1DSQOR2RO6I202GTCTPDHKCB93").unwrap(),
            vec![
                DNSType::A,
                DNSType::NS,
                DNSType::SOA,
                DNSType::MX,
                DNSType::TXT,
                DNSType::AAAA,
                DNSType::RRSIG,
                DNSType::DNSKEY,
                DNSType::NSEC3PARAM,
            ],
        );
        let nsec3_bitstream = vec![
            0x01, 0x00, 0x00, 0x05, 0x08, 0x4c, 0xd7, 0xb0, 0x54, 0xf8, 0x76, 0x95, 0x6c, 0x14,
            0x0d, 0x22, 0x23, 0xd4, 0x2d, 0xe6, 0xb1, 0xb1, 0x6f, 0x06, 0x90, 0x80, 0x28, 0x75,
            0x9d, 0xcb, 0x63, 0x46, 0x2d, 0x23, 0x00, 0x07, 0x62, 0x01, 0x80, 0x08, 0x00, 0x02,
            0x90,
        ];
        (nsec3_bitstream, nsec3_str.to_owned(), nsec3_struct.unwrap())
    }

    #[test]
    fn dns_nsec3_from_str() {
        let (_, nsec_str, nsec_struct) = get_example_nsec3();
        match DnsTypeNSEC3::from_str(nsec_str.as_str(), None) {
            Ok(nsec) => {
                assert_eq!(nsec, nsec_struct);
            }
            Err(err) => assert!(
                false,
                format!("nsec3 from_str method got a unexpected failure: {:?}", err)
            ),
        }
    }

    #[test]
    fn nsec3_binary_serialize() {
        let (bin_arr, nsec_str, nsec_struct) = get_example_nsec3();
        assert_eq!(DnsTypeNSEC3::decode(&bin_arr, None).unwrap(), nsec_struct);
        match nsec_struct.encode(None) {
            Ok(nsec_vec) => {
                assert_eq!(nsec_vec.as_slice(), &bin_arr[..]);
            }
            _ => assert!(false, "encode nsec fail"),
        }
        assert_eq!(nsec_str, nsec_struct.to_string());
    }

    #[test]
    fn test_nsec3_hash_codec() {
        let str = "1KH27L1DSQOR2RO6I202GTCTPDHKCB93";

        let result = encode_nsec3_hash_from_str(str);
        assert_eq!(result.is_ok(), true);

        let input = [
            0x0d, 0x22, 0x23, 0xd4, 0x2d, 0xe6, 0xb1, 0xb1, 0x6f, 0x06, 0x90, 0x80, 0x28, 0x75,
            0x9d, 0xcb, 0x63, 0x46, 0x2d, 0x23,
        ];
        assert_eq!(result.unwrap(), input);

        let result = decode_nsec3_hash_to_string(&input);
        assert_eq!(result, str);
    }
}
