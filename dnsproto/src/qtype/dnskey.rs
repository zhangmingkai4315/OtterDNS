use crate::meta::DNSType;
use crate::qtype::ds::AlgorithemType;
use crate::qtype::{CompressionType, DNSWireFrame};
use nom::character::complete::{digit1, multispace0};
use nom::number::complete::{be_u16, be_u8};
use otterlib::errors::{DNSProtoErr, ParseZoneDataErr};
use std::any::Any;
use std::str::FromStr;
use std::{fmt, fmt::Formatter};

// https://tools.ietf.org/html/rfc4034#section-2.1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |              Flags            |    Protocol   |   Algorithm   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// /                                                               /
// /                            Public Key                         /
// /                                                               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug, PartialEq)]
pub struct DnsTypeDNSKEY {
    flags: u16,
    protocol_type: u8, // must be 3
    algorithem_type: AlgorithemType,
    public_key: Vec<u8>,
}

named_args!(parse_dnskey<'a>(size: usize)<DnsTypeDNSKEY>,
    do_parse!(
        flags: be_u16>>
        protocol_type: be_u8>>
        algorithem_type: be_u8>>
        publick_key: take!(size - 4)>>
        ( DnsTypeDNSKEY::new_from_raw(
            flags,
            protocol_type,
            algorithem_type,
            publick_key,
        )
            )

    )
);

impl DnsTypeDNSKEY {
    pub fn new(
        flags: u16,
        algorithem_type: AlgorithemType,
        public_key: String, // base64
    ) -> Result<Self, ParseZoneDataErr> {
        match base64::decode(public_key.as_str()) {
            Ok(decoded) => Ok(DnsTypeDNSKEY {
                flags,
                protocol_type: 3,
                algorithem_type,
                public_key: decoded,
            }),
            Err(err) => Err(ParseZoneDataErr::GeneralErr(format!(
                "public_key can't be decode to bytes: {}",
                err.to_string(),
            ))),
        }
    }
    pub fn new_from_raw(
        flags: u16,
        protocol_type: u8,
        algorithm_type: u8,
        public_key: &[u8],
    ) -> Self {
        DnsTypeDNSKEY {
            flags,
            protocol_type,
            algorithem_type: AlgorithemType::from_u8(algorithm_type),
            public_key: public_key.to_vec(),
        }
    }

    // example : "256 3 8 AwEAAa+HvD7XXjmL+1htThUQyZW7oWGnjzKHJASg3TSR5Bmu5LfnSVW7fxqZa2oAYo2ionIQWy
    //            qAj/loApzg8GNMhyIibftPJso54uWRQ2GaoMrwLD5SLu676kf7urJq6nqdjNC0aJM/C888li69lVH6tiu2
    //            tZm1NH3cmgfnMUJpD60bsrDUqs7XwftmNkdkHa4ltQbM3UNPyfTaNBQYoH3wpOpSjdk3tyDRnreBO6Idrw
    //            +DGf/rve4sL3qiSaXfYIkcwAwozxR34iHU5dbCDs8S6FmZYhoSVKVgNSUkudxhd9/6RrZkYRgvwRsQXl3U
    //            wsacU1DsXcORqIC+7NlQ6M2OJVU="
    pub fn from_str(str: &str) -> Result<Self, ParseZoneDataErr> {
        let str = str.trim();
        let (rest, flags) = digit1(str)?;
        let flags = u16::from_str(flags)?;
        let (rest, _) = multispace0(rest)?;
        let (rest, protocol_type) = digit1(rest)?;
        let protocol_type = u8::from_str(protocol_type)?;
        let (rest, _) = multispace0(rest)?;
        let (rest, algorithm_type) = digit1(rest)?;
        let algorithm_type = u8::from_str(algorithm_type)?;
        let (pk, _) = multispace0(rest)?;
        if protocol_type != 3 {
            return Err(ParseZoneDataErr::GeneralErr(format!(
                "unknown protocol number: {} for dnskey",
                protocol_type
            )));
        }
        let algorithem = AlgorithemType::from_u8(algorithm_type);
        if algorithem == AlgorithemType::Unknown {
            return Err(ParseZoneDataErr::GeneralErr(format!(
                "unknown algorithm_type number: {} for dnskey",
                algorithm_type
            )));
        }
        match base64::decode(pk) {
            Ok(decode) => Ok(DnsTypeDNSKEY::new_from_raw(
                flags,
                protocol_type,
                algorithm_type,
                decode.as_slice(),
            )),
            Err(err) => Err(ParseZoneDataErr::GeneralErr(format!(
                "decode dnskey base64 fail:{}",
                err.to_string()
            ))),
        }
    }
}

impl fmt::Display for DnsTypeDNSKEY {
    fn fmt(&self, format: &mut Formatter<'_>) -> fmt::Result {
        write!(
            format,
            "{} {} {} {}",
            self.flags,
            self.protocol_type,
            self.algorithem_type as u8,
            base64::encode(&self.public_key)
        )
    }
}
impl DNSWireFrame for DnsTypeDNSKEY {
    fn decode(data: &[u8], _: Option<&[u8]>) -> Result<Self, DNSProtoErr> {
        match parse_dnskey(data, data.len()) {
            Ok((_, mx)) => Ok(mx),
            Err(_err) => Err(DNSProtoErr::PacketParseError),
        }
    }

    fn get_type(&self) -> DNSType {
        DNSType::DNSKEY
    }

    fn encode(&self, _: CompressionType) -> Result<Vec<u8>, DNSProtoErr> {
        let mut data = vec![];
        data.extend_from_slice(&self.flags.to_be_bytes()[..]);
        data.push(self.protocol_type);
        data.push(self.algorithem_type.into());
        data.extend_from_slice(&self.public_key.as_slice());
        Ok(data)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod test {
    use crate::qtype::dnskey::DnsTypeDNSKEY;
    use crate::qtype::ds::AlgorithemType;
    use crate::qtype::DNSWireFrame;

    fn get_example_dnskey() -> [(DnsTypeDNSKEY, String, Vec<u8>); 2] {
        let zsk = "AwEAAaxMabJOjpV+ccAKgWjP1UBfVBN+VCFu92scQydffI3tNiFJ35GHGV8ktSQn72LYgMHUlibAX10D5a8BR2+6RSA6pUNIMnUuLwMAa03avcbvQcX8eG+C3Ys3VBi6sYMw7hXlxhZHMq9GPtsXtOjZfm9DAe7rz7T1pO5M0YniheXR";
        let ksk =  "AwEAAd4vztGWGI+qShKPs9MaXFqZIDgcnoUh59OnUHOi7w67q5oMXynRF2W1nyfg9RPV7ZY7oR2IaDm3/avBMUYokFLsyE8NavUfZORhoN0hnC6dRiv8VrYDCjj5VSh7kwk157mm3BxLn1XTs9Jys44bJ17fNxNjS4AGdUa94pOdGPTycSeJ76dUtWp8jz9ffborCWvsXtp3AsEJs7eFAmOJIqllE3gl4w2GmEKaq+AdYG7j1T5uWVg+sIZ1GCofi/+1ml6U588bqKzUSkjA4Gn+ZoLToviPSYAIC2/KeEYt1RYzUc3H72ScM+Kv2o+ZtC2YRSmrnVGqcSTriysYdlzmU7c=";
        let zsk_str = "256 3 8 ".to_owned() + zsk;
        let ksk_str = "257 3 8 ".to_owned() + ksk;

        let ksk_struct =
            DnsTypeDNSKEY::new(257, AlgorithemType::RSASHA256, ksk.to_owned()).unwrap();
        let zsk_struct =
            DnsTypeDNSKEY::new(256, AlgorithemType::RSASHA256, zsk.to_owned()).unwrap();
        let zsk_binary = vec![
            0x01u8, 0x00, 0x03, 0x08, 0x03, 0x01, 0x00, 0x01, 0xac, 0x4c, 0x69, 0xb2, 0x4e, 0x8e,
            0x95, 0x7e, 0x71, 0xc0, 0x0a, 0x81, 0x68, 0xcf, 0xd5, 0x40, 0x5f, 0x54, 0x13, 0x7e,
            0x54, 0x21, 0x6e, 0xf7, 0x6b, 0x1c, 0x43, 0x27, 0x5f, 0x7c, 0x8d, 0xed, 0x36, 0x21,
            0x49, 0xdf, 0x91, 0x87, 0x19, 0x5f, 0x24, 0xb5, 0x24, 0x27, 0xef, 0x62, 0xd8, 0x80,
            0xc1, 0xd4, 0x96, 0x26, 0xc0, 0x5f, 0x5d, 0x03, 0xe5, 0xaf, 0x01, 0x47, 0x6f, 0xba,
            0x45, 0x20, 0x3a, 0xa5, 0x43, 0x48, 0x32, 0x75, 0x2e, 0x2f, 0x03, 0x00, 0x6b, 0x4d,
            0xda, 0xbd, 0xc6, 0xef, 0x41, 0xc5, 0xfc, 0x78, 0x6f, 0x82, 0xdd, 0x8b, 0x37, 0x54,
            0x18, 0xba, 0xb1, 0x83, 0x30, 0xee, 0x15, 0xe5, 0xc6, 0x16, 0x47, 0x32, 0xaf, 0x46,
            0x3e, 0xdb, 0x17, 0xb4, 0xe8, 0xd9, 0x7e, 0x6f, 0x43, 0x01, 0xee, 0xeb, 0xcf, 0xb4,
            0xf5, 0xa4, 0xee, 0x4c, 0xd1, 0x89, 0xe2, 0x85, 0xe5, 0xd1,
        ];

        let ksk_binary = vec![
            0x01u8, 0x01, 0x03, 0x08, 0x03, 0x01, 0x00, 0x01, 0xde, 0x2f, 0xce, 0xd1, 0x96, 0x18,
            0x8f, 0xaa, 0x4a, 0x12, 0x8f, 0xb3, 0xd3, 0x1a, 0x5c, 0x5a, 0x99, 0x20, 0x38, 0x1c,
            0x9e, 0x85, 0x21, 0xe7, 0xd3, 0xa7, 0x50, 0x73, 0xa2, 0xef, 0x0e, 0xbb, 0xab, 0x9a,
            0x0c, 0x5f, 0x29, 0xd1, 0x17, 0x65, 0xb5, 0x9f, 0x27, 0xe0, 0xf5, 0x13, 0xd5, 0xed,
            0x96, 0x3b, 0xa1, 0x1d, 0x88, 0x68, 0x39, 0xb7, 0xfd, 0xab, 0xc1, 0x31, 0x46, 0x28,
            0x90, 0x52, 0xec, 0xc8, 0x4f, 0x0d, 0x6a, 0xf5, 0x1f, 0x64, 0xe4, 0x61, 0xa0, 0xdd,
            0x21, 0x9c, 0x2e, 0x9d, 0x46, 0x2b, 0xfc, 0x56, 0xb6, 0x03, 0x0a, 0x38, 0xf9, 0x55,
            0x28, 0x7b, 0x93, 0x09, 0x35, 0xe7, 0xb9, 0xa6, 0xdc, 0x1c, 0x4b, 0x9f, 0x55, 0xd3,
            0xb3, 0xd2, 0x72, 0xb3, 0x8e, 0x1b, 0x27, 0x5e, 0xdf, 0x37, 0x13, 0x63, 0x4b, 0x80,
            0x06, 0x75, 0x46, 0xbd, 0xe2, 0x93, 0x9d, 0x18, 0xf4, 0xf2, 0x71, 0x27, 0x89, 0xef,
            0xa7, 0x54, 0xb5, 0x6a, 0x7c, 0x8f, 0x3f, 0x5f, 0x7d, 0xba, 0x2b, 0x09, 0x6b, 0xec,
            0x5e, 0xda, 0x77, 0x02, 0xc1, 0x09, 0xb3, 0xb7, 0x85, 0x02, 0x63, 0x89, 0x22, 0xa9,
            0x65, 0x13, 0x78, 0x25, 0xe3, 0x0d, 0x86, 0x98, 0x42, 0x9a, 0xab, 0xe0, 0x1d, 0x60,
            0x6e, 0xe3, 0xd5, 0x3e, 0x6e, 0x59, 0x58, 0x3e, 0xb0, 0x86, 0x75, 0x18, 0x2a, 0x1f,
            0x8b, 0xff, 0xb5, 0x9a, 0x5e, 0x94, 0xe7, 0xcf, 0x1b, 0xa8, 0xac, 0xd4, 0x4a, 0x48,
            0xc0, 0xe0, 0x69, 0xfe, 0x66, 0x82, 0xd3, 0xa2, 0xf8, 0x8f, 0x49, 0x80, 0x08, 0x0b,
            0x6f, 0xca, 0x78, 0x46, 0x2d, 0xd5, 0x16, 0x33, 0x51, 0xcd, 0xc7, 0xef, 0x64, 0x9c,
            0x33, 0xe2, 0xaf, 0xda, 0x8f, 0x99, 0xb4, 0x2d, 0x98, 0x45, 0x29, 0xab, 0x9d, 0x51,
            0xaa, 0x71, 0x24, 0xeb, 0x8b, 0x2b, 0x18, 0x76, 0x5c, 0xe6, 0x53, 0xb7,
        ];
        [
            (zsk_struct, zsk_str, zsk_binary),
            (ksk_struct, ksk_str, ksk_binary),
        ]
    }

    #[test]
    fn dnskey_from_str() {
        for tc in &get_example_dnskey() {
            match DnsTypeDNSKEY::from_str(tc.1.as_str()) {
                Ok(dnskey) => {
                    assert_eq!(dnskey, tc.0);
                }
                Err(err) => assert!(
                    false,
                    format!("dnskey from_str method got a unexpected failure: {:?}", err)
                ),
            }
        }
    }

    #[test]
    fn dnskey_binary_serialize() {
        for tc in &get_example_dnskey() {
            assert_eq!(DnsTypeDNSKEY::decode(&tc.2, None).unwrap(), tc.0);
            match tc.0.encode(None) {
                Ok(dnskey) => {
                    assert_eq!(dnskey.as_slice(), &tc.2[..]);
                }
                _ => assert!(false, "encode dnskey fail"),
            }
            assert_eq!(tc.1, tc.0.to_string());
        }
    }
}
