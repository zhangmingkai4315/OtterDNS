use crate::dnsname::{parse_name, DNSName};
use crate::meta::DNSType;
use crate::qtype::ds::AlgorithemType;
use crate::qtype::soa::is_not_space;
use crate::qtype::{CompressionType, DNSWireFrame};
use nom::bytes::complete::take_while;
use nom::character::complete::{digit1, multispace0};
use nom::combinator::rest;
use nom::number::complete::{be_u16, be_u32, be_u8};
use otterlib::errors::{DNSProtoErr, ParseZoneDataErr};
use std::any::Any;
use std::str::FromStr;
use std::{fmt, fmt::Formatter};

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |        Type Covered           |  Algorithm    |     Labels    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Original TTL                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                      Signature Expiration                     |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                      Signature Inception                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |            Key Tag            |                               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         Signer's Name         /
// /                                                               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// /                                                               /
// /                            Signature                          /
// /                                                               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[derive(Debug, PartialEq)]
pub struct DnsTypeRRSIG {
    rrsig_type: u16,
    algorithm_type: u8,
    original_ttl: u32,
    expiration: u32,
    inception: u32,
    key_tag: u16,
    signer: DNSName,
    signature: Vec<u8>,
}

named_args!(parse_rrsig<'a>(original: Option<&[u8]>, size: usize)<DnsTypeRRSIG>,
    do_parse!(
        rrsig_type: be_u16>>
        algorithm_type: be_u8>>
        original_ttl: be_u32>>
        expiration: be_u32>>
        inception: be_u32>>
        key_tag:   be_u16>>
        signer: call!(parse_name, original.unwrap_or(&[]))>>
        signature: call!(rest)>>
        ( DnsTypeRRSIG::new(
            rrsig_type,
            algorithm_type,
            original_ttl,
            expiration,
            inception,
            key_tag,
            signer,
            signature.to_vec(),
          )
        )

    )
);

impl DnsTypeRRSIG {
    pub fn new(
        rrsig_type: u16,
        algorithm_type: u8,
        original_ttl: u32,
        expiration: u32,
        inception: u32,
        key_tag: u16,
        signer: DNSName,
        signature: Vec<u8>,
    ) -> Self {
        DnsTypeRRSIG {
            rrsig_type,
            algorithm_type,
            original_ttl,
            expiration,
            inception,
            key_tag,
            signer,
            signature,
        }
    }

    // example : "8 0 86400 20210422050000 20210409040000 14631 . W45Xjg7WewB+rNjMHDTpHlmvwT+L3VamaProC1FMIUFGZRcnFd41GSkK c2i2kgtcVjxIuYiw6kVgd7MXxaEsgW6wIexCq8H1JuDJIl/lDRZOPfzy 2IxEvqCFV01beVFnbWAMYOAa6u3W/DB2+uJ7+GNJPzN7vLAsNpFzFvxo 5jxY47I+WU0pFFxYlWoQ29Xzq2MBkwU8pPRovlN1nexk8I+Uwcw6fmUL LXg4U3U4+UK76Vhb0IMRFZFa44n3RjGwIu3lG+5Z16Fo3y8Xo+XA8ojt
    //            wvXpz1hfaKd8f/CMzs9dLSJp5TA15DQ9KAaqKepZmgJvajt/wYUMpTeX 4N0kuA=="
    pub fn from_str(str: &str) -> Result<Self, ParseZoneDataErr> {
        let (rest, rrsig_type) = digit1(str)?;
        let rrsig_type = u16::from_str(rrsig_type)?;
        let (rest, _) = multispace0(rest)?;
        let (rest, algorithm_type) = digit1(rest)?;
        let algorithm_type = u8::from_str(algorithm_type)?;
        let (rest, _) = multispace0(rest)?;
        let (rest, original_ttl) = digit1(rest)?;
        let original_ttl = u32::from_str(original_ttl)?;
        let (rest, _) = multispace0(rest)?;
        let (rest, expiration) = digit1(rest)?;
        let expiration = u32::from_str(expiration)?;
        let (rest, _) = multispace0(rest)?;
        let (rest, inception) = digit1(rest)?;
        let inception = u32::from_str(inception)?;
        let (rest, _) = multispace0(rest)?;
        let (rest, key_tag) = digit1(rest)?;
        let key_tag = u16::from_str(key_tag)?;
        let (rest, _) = multispace0(rest)?;
        let (rest, signer) = take_while(is_not_space)(rest)?;
        let (rest, _) = multispace0(rest)?;
        let (_, signature) = take_while(is_not_space)(rest)?;
        // let (rest, _) = multispace0(rest)?;
        match base64::decode(signature) {
            Ok(decode) => Ok(DnsTypeRRSIG::new(
                rrsig_type,
                algorithm_type,
                original_ttl,
                expiration,
                inception,
                key_tag,
                DNSName::new(signer, None)?,
                decode,
            )),
            Err(err) => Err(ParseZoneDataErr::GeneralErr(format!(
                "decode rrsig base64 fail:{}",
                err.to_string()
            ))),
        }
    }
}

impl fmt::Display for DnsTypeRRSIG {
    fn fmt(&self, format: &mut Formatter<'_>) -> fmt::Result {
        write!(
            format,
            "{} {} {} {} {} {} {} {}",
            self.rrsig_type,
            self.algorithm_type,
            self.original_ttl,
            self.expiration,
            self.inception,
            self.key_tag,
            self.signer.to_string(),
            base64::encode(self.signature.as_slice())
        )
    }
}
impl DNSWireFrame for DnsTypeRRSIG {
    fn decode(data: &[u8], original: Option<&[u8]>) -> Result<Self, DNSProtoErr> {
        match parse_rrsig(data, original, data.len()) {
            Ok((_, rrsig)) => Ok(rrsig),
            Err(_err) => Err(DNSProtoErr::PacketParseError),
        }
    }

    fn get_type(&self) -> DNSType {
        DNSType::RRSIG
    }

    fn encode(&self, _: CompressionType) -> Result<Vec<u8>, DNSProtoErr> {
        let mut data = vec![];
        // data.extend_from_slice(&self.key_tag.to_be_bytes()[..]);
        // data.push(self.algorithm_type.into());
        // data.push(self.digest_type.into());
        // data.extend_from_slice(&self.digest.as_slice());
        Ok(data)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// #[cfg(test)]
// mod test {
//     use crate::qtype::ds::{AlgorithemType, DigestType, DnsTypeDS};
//     use crate::qtype::DNSWireFrame;
//     use otterlib::errors::ParseZoneDataErr;
//
//     fn get_example_ds() -> (&'static str, Result<DnsTypeDS, ParseZoneDataErr>) {
//         let ds_str = "30909 8 2 E2D3C916F6DEEAC73294E8268FB5885044A833FC5459588F4A9184CFC41A5766";
//         let ds_struct = DnsTypeDS::new(
//             30909,
//             AlgorithemType::RSASHA256,
//             DigestType::SHA256,
//             "E2D3C916F6DEEAC73294E8268FB5885044A833FC5459588F4A9184CFC41A5766".to_owned(),
//         );
//         (ds_str, ds_struct)
//     }
//
//     #[test]
//     fn dns_ds_from_str() {
//         let (ds_str, ds_struct) = get_example_ds();
//         if ds_struct.is_err() {
//             assert!(false, "ds new method got a unexpected failure");
//             return;
//         }
//         let ds_struct = ds_struct.unwrap();
//         match DnsTypeDS::from_str(ds_str) {
//             Ok(ds) => {
//                 assert_eq!(ds, ds_struct);
//                 assert_eq!(ds_str.to_owned(), ds_str.to_string())
//             }
//             Err(err) => assert!(
//                 false,
//                 format!("ds from_str method got a unexpected failure: {:?}", err)
//             ),
//         }
//     }
//
//     #[test]
//     fn ds_binary_serialize() {
//         let (ds_str, ds_struct) = get_example_ds();
//         let ds_struct = ds_struct.unwrap();
//         let bin_arr = [
//             0x78, 0xbd, 0x08, 0x02, 0xe2, 0xd3, 0xc9, 0x16, 0xf6, 0xde, 0xea, 0xc7, 0x32, 0x94,
//             0xe8, 0x26, 0x8f, 0xb5, 0x88, 0x50, 0x44, 0xa8, 0x33, 0xfc, 0x54, 0x59, 0x58, 0x8f,
//             0x4a, 0x91, 0x84, 0xcf, 0xc4, 0x1a, 0x57, 0x66,
//         ];
//         assert_eq!(DnsTypeDS::decode(&bin_arr, None).unwrap(), ds_struct);
//         match ds_struct.encode(None) {
//             Ok(ds_vec) => {
//                 assert_eq!(ds_vec.as_slice(), &bin_arr[..]);
//             }
//             _ => assert!(false, "encode ds fail"),
//         }
//         assert_eq!(ds_str, ds_struct.to_string());
//     }
// }
