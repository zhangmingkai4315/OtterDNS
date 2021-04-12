use crate::dnsname::{parse_name, DNSName};
use crate::meta::DNSType;
use crate::qtype::soa::is_not_space;
use crate::qtype::{CompressionType, DNSWireFrame};
use nom::bytes::complete::take_while;
use nom::character::complete::{digit1, multispace0};
use nom::combinator::rest;
use nom::number::complete::{be_u16, be_u32, be_u8};
use otterlib::errors::{DNSProtoErr, ParseZoneDataErr};
use std::any::Any;
use std::convert::TryFrom;
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
    labels: u8,
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
        labels: be_u8 >>
        original_ttl: be_u32>>
        expiration: be_u32>>
        inception: be_u32>>
        key_tag:   be_u16>>
        signer: call!(parse_name, original.unwrap_or(&[]))>>
        signature: call!(rest)>>
        ( DnsTypeRRSIG::new(
            rrsig_type,
            algorithm_type,
            labels,
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
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rrsig_type: u16,
        algorithm_type: u8,
        labels: u8,
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
            labels,
            original_ttl,
            expiration,
            inception,
            key_tag,
            signer,
            signature,
        }
    }

    // example : "SOA 8 0 86400 20210422050000 20210409040000 14631 . W45Xjg7WewB+rNjMHDTpHlmvwT+L3VamaProC1FMIUFGZRcnFd41GSkK c2i2kgtcVjxIuYiw6kVgd7MXxaEsgW6wIexCq8H1JuDJIl/lDRZOPfzy 2IxEvqCFV01beVFnbWAMYOAa6u3W/DB2+uJ7+GNJPzN7vLAsNpFzFvxo 5jxY47I+WU0pFFxYlWoQ29Xzq2MBkwU8pPRovlN1nexk8I+Uwcw6fmUL LXg4U3U4+UK76Vhb0IMRFZFa44n3RjGwIu3lG+5Z16Fo3y8Xo+XA8ojt
    //            wvXpz1hfaKd8f/CMzs9dLSJp5TA15DQ9KAaqKepZmgJvajt/wYUMpTeX 4N0kuA=="
    pub fn from_str(str: &str) -> Result<Self, ParseZoneDataErr> {
        let (rest, rrsig_type) = take_while(is_not_space)(str)?;
        let rrsig_type = match DNSType::from_str(rrsig_type) {
            Some(value) => value,
            _ => {
                return Err(ParseZoneDataErr::GeneralErr(
                    "unknown rrsig type".to_owned(),
                ))
            }
        };
        let rrsig_type = rrsig_type as u16;

        let (rest, _) = multispace0(rest)?;
        let (rest, algorithm_type) = digit1(rest)?;
        let algorithm_type = u8::from_str(algorithm_type)?;
        let (rest, _) = multispace0(rest)?;
        let (rest, labels) = digit1(rest)?;
        let labels = u8::from_str(labels)?;
        let (rest, _) = multispace0(rest)?;
        let (rest, original_ttl) = digit1(rest)?;
        let original_ttl = u32::from_str(original_ttl)?;

        let (rest, _) = multispace0(rest)?;
        let (rest, expiration) = digit1(rest)?;
        let (rest, _) = multispace0(rest)?;
        let (rest, inception) = digit1(rest)?;
        let (rest, _) = multispace0(rest)?;
        let (rest, key_tag) = digit1(rest)?;
        let key_tag = u16::from_str(key_tag)?;
        let (rest, _) = multispace0(rest)?;
        let (rest, signer) = take_while(is_not_space)(rest)?;
        let (rest, _) = multispace0(rest)?;
        let (_, signature) = take_while(is_not_space)(rest)?;
        // let (rest, _) = multispace0(rest)?;

        let expiration = time_string_to_u32(expiration)?;
        let inception = time_string_to_u32(inception)?;
        let name = DNSName::new(signer, None)?;
        match base64::decode(signature) {
            Ok(decode) => Ok(DnsTypeRRSIG::new(
                rrsig_type,
                algorithm_type,
                labels,
                original_ttl,
                expiration,
                inception,
                key_tag,
                name,
                decode,
            )),
            Err(err) => Err(ParseZoneDataErr::GeneralErr(format!(
                "decode rrsig base64 fail:{}",
                err.to_string()
            ))),
        }
    }
}

fn time_to_string(time_val: u32) -> String {
    let naive = chrono::NaiveDateTime::from_timestamp(time_val as i64, 0);
    // Create a normal DateTime from the NaiveDateTime
    let datetime: chrono::DateTime<chrono::Utc> = chrono::DateTime::from_utc(naive, chrono::Utc);
    let newdate = datetime.format("%Y%m%d%H%M%S");
    newdate.to_string()
}

fn time_string_to_u32(time_val: &str) -> Result<u32, ParseZoneDataErr> {
    match chrono::NaiveDateTime::parse_from_str(time_val, "%Y%m%d%H%M%S") {
        Ok(native) => Ok(native.timestamp() as u32),
        _ => Err(ParseZoneDataErr::GeneralErr("parse time error".to_owned())),
    }
}
impl fmt::Display for DnsTypeRRSIG {
    fn fmt(&self, format: &mut Formatter<'_>) -> fmt::Result {
        write!(
            format,
            "{} {} {} {} {} {} {} {} {}",
            DNSType::try_from(self.rrsig_type).unwrap_or(DNSType::Unknown),
            self.algorithm_type,
            self.labels,
            self.original_ttl,
            time_to_string(self.expiration),
            time_to_string(self.inception),
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

    fn encode(&self, compression: CompressionType) -> Result<Vec<u8>, DNSProtoErr> {
        let mut data = vec![];

        data.extend_from_slice(&self.rrsig_type.to_be_bytes()[..]);
        data.push(self.algorithm_type);
        data.push(self.labels);
        data.extend_from_slice(&self.original_ttl.to_be_bytes()[..]);
        data.extend_from_slice(&self.expiration.to_be_bytes()[..]);
        data.extend_from_slice(&self.inception.to_be_bytes()[..]);
        data.extend_from_slice(&self.key_tag.to_be_bytes()[..]);
        data.extend_from_slice(&self.signer.to_binary(compression));
        data.extend_from_slice(&self.signature.as_slice());
        Ok(data)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod test {
    use crate::dnsname::DNSName;
    use crate::meta::DNSType;
    use crate::qtype::ds::AlgorithemType;
    use crate::qtype::rrsig::DnsTypeRRSIG;
    use crate::qtype::DNSWireFrame;

    fn get_example_rrsig() -> (String, DnsTypeRRSIG) {
        let rrsig_str = "SOA 8 0 86400 20210422050000 20210409040000 14631 . ";
        let rrsig_signatrue = "W45Xjg7WewB+rNjMHDTpHlmvwT+L3VamaProC1FMIUFGZRcnFd41GSkKc2i2kgtcVjxIuYiw6kVgd7MXxaEsgW6wIexCq8H1JuDJIl/lDRZOPfzy2IxEvqCFV01beVFnbWAMYOAa6u3W/DB2+uJ7+GNJPzN7vLAsNpFzFvxo5jxY47I+WU0pFFxYlWoQ29Xzq2MBkwU8pPRovlN1nexk8I+Uwcw6fmULLXg4U3U4+UK76Vhb0IMRFZFa44n3RjGwIu3lG+5Z16Fo3y8Xo+XA8ojtwvXpz1hfaKd8f/CMzs9dLSJp5TA15DQ9KAaqKepZmgJvajt/wYUMpTeX4N0kuA==";

        let rrsig_struct = DnsTypeRRSIG::new(
            DNSType::SOA as u16,
            AlgorithemType::RSASHA256.into(),
            0,
            86400,
            1619067600,
            1617940800,
            14631,
            DNSName::new(".", None).unwrap(),
            base64::decode(rrsig_signatrue).unwrap(),
        );
        (rrsig_str.to_owned() + rrsig_signatrue, rrsig_struct)
    }

    #[test]
    fn dns_rrsig_from_str() {
        let (rrsig_str, rrsig_struct) = get_example_rrsig();
        match DnsTypeRRSIG::from_str(rrsig_str.as_str()) {
            Ok(rrsig) => {
                assert_eq!(rrsig, rrsig_struct);
                assert_eq!(rrsig_str.to_owned(), rrsig_struct.to_string())
            }
            Err(err) => assert!(
                false,
                format!("from_str method got a unexpected failure: {:?}", err)
            ),
        }
    }

    #[test]
    fn rrsig_binary_serialize() {
        let (rrsig, rrsig_struct) = get_example_rrsig();
        let bin_arr = [
            0x00, 0x06, 0x08, 0x00, 0x00, 0x01, 0x51, 0x80, 0x60, 0x81, 0x02, 0xd0, 0x60, 0x6f,
            0xd1, 0x40, 0x39, 0x27, 0x00, 0x5b, 0x8e, 0x57, 0x8e, 0x0e, 0xd6, 0x7b, 0x00, 0x7e,
            0xac, 0xd8, 0xcc, 0x1c, 0x34, 0xe9, 0x1e, 0x59, 0xaf, 0xc1, 0x3f, 0x8b, 0xdd, 0x56,
            0xa6, 0x68, 0xfa, 0xe8, 0x0b, 0x51, 0x4c, 0x21, 0x41, 0x46, 0x65, 0x17, 0x27, 0x15,
            0xde, 0x35, 0x19, 0x29, 0x0a, 0x73, 0x68, 0xb6, 0x92, 0x0b, 0x5c, 0x56, 0x3c, 0x48,
            0xb9, 0x88, 0xb0, 0xea, 0x45, 0x60, 0x77, 0xb3, 0x17, 0xc5, 0xa1, 0x2c, 0x81, 0x6e,
            0xb0, 0x21, 0xec, 0x42, 0xab, 0xc1, 0xf5, 0x26, 0xe0, 0xc9, 0x22, 0x5f, 0xe5, 0x0d,
            0x16, 0x4e, 0x3d, 0xfc, 0xf2, 0xd8, 0x8c, 0x44, 0xbe, 0xa0, 0x85, 0x57, 0x4d, 0x5b,
            0x79, 0x51, 0x67, 0x6d, 0x60, 0x0c, 0x60, 0xe0, 0x1a, 0xea, 0xed, 0xd6, 0xfc, 0x30,
            0x76, 0xfa, 0xe2, 0x7b, 0xf8, 0x63, 0x49, 0x3f, 0x33, 0x7b, 0xbc, 0xb0, 0x2c, 0x36,
            0x91, 0x73, 0x16, 0xfc, 0x68, 0xe6, 0x3c, 0x58, 0xe3, 0xb2, 0x3e, 0x59, 0x4d, 0x29,
            0x14, 0x5c, 0x58, 0x95, 0x6a, 0x10, 0xdb, 0xd5, 0xf3, 0xab, 0x63, 0x01, 0x93, 0x05,
            0x3c, 0xa4, 0xf4, 0x68, 0xbe, 0x53, 0x75, 0x9d, 0xec, 0x64, 0xf0, 0x8f, 0x94, 0xc1,
            0xcc, 0x3a, 0x7e, 0x65, 0x0b, 0x2d, 0x78, 0x38, 0x53, 0x75, 0x38, 0xf9, 0x42, 0xbb,
            0xe9, 0x58, 0x5b, 0xd0, 0x83, 0x11, 0x15, 0x91, 0x5a, 0xe3, 0x89, 0xf7, 0x46, 0x31,
            0xb0, 0x22, 0xed, 0xe5, 0x1b, 0xee, 0x59, 0xd7, 0xa1, 0x68, 0xdf, 0x2f, 0x17, 0xa3,
            0xe5, 0xc0, 0xf2, 0x88, 0xed, 0xc2, 0xf5, 0xe9, 0xcf, 0x58, 0x5f, 0x68, 0xa7, 0x7c,
            0x7f, 0xf0, 0x8c, 0xce, 0xcf, 0x5d, 0x2d, 0x22, 0x69, 0xe5, 0x30, 0x35, 0xe4, 0x34,
            0x3d, 0x28, 0x06, 0xaa, 0x29, 0xea, 0x59, 0x9a, 0x02, 0x6f, 0x6a, 0x3b, 0x7f, 0xc1,
            0x85, 0x0c, 0xa5, 0x37, 0x97, 0xe0, 0xdd, 0x24, 0xb8,
        ];
        assert_eq!(DnsTypeRRSIG::decode(&bin_arr, None).unwrap(), rrsig_struct);
        match rrsig_struct.encode(None) {
            Ok(rr_vec) => {
                assert_eq!(rr_vec.as_slice(), &bin_arr[..]);
            }
            _ => assert!(false, "encode ds fail"),
        }
        assert_eq!(rrsig, rrsig_struct.to_string());
    }
}
