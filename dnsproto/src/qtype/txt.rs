use crate::meta::DNSType;
use crate::qtype::{CompressionType, DNSWireFrame};
use otterlib::errors::DNSProtoErr;
use std::any::Any;
use std::fmt::{self, Formatter};
use std::str::FromStr;

#[derive(Debug, PartialEq, Clone)]
pub struct DnsTypeTXT {
    pub(crate) text: String,
}

impl FromStr for DnsTypeTXT {
    type Err = DNSProtoErr;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Ok(DnsTypeTXT {
            text: text.to_string(),
        })
    }
}

impl DnsTypeTXT {
    pub fn new(text: &str) -> Result<Self, DNSProtoErr> {
        Ok(DnsTypeTXT {
            text: text.to_string(),
        })
    }
    pub fn decode(data: &[u8], _: Option<&[u8]>) -> Result<Self, DNSProtoErr> {
        let data_length = data.len();
        if data_length == 0 {
            return Err(DNSProtoErr::PacketParseError);
        }

        let txt_length = data[0];
        if data.len() < (txt_length as usize + 1) {
            return Err(DNSProtoErr::PacketParseError);
        }
        match std::str::from_utf8(&data[1..=(txt_length as usize)]) {
            Ok(text_str) => DnsTypeTXT::new(text_str),
            _ => Err(DNSProtoErr::PacketParseError),
        }
    }
}

impl fmt::Display for DnsTypeTXT {
    fn fmt(&self, format: &mut Formatter<'_>) -> fmt::Result {
        write!(format, "{}", self.text)
    }
}

impl DNSWireFrame for DnsTypeTXT {
    fn get_type(&self) -> DNSType {
        DNSType::TXT
    }
    fn encode(&self, _: CompressionType) -> Result<Vec<u8>, DNSProtoErr> {
        let text_bytes = self.text.as_bytes();
        let size = text_bytes.len();
        if size > (u8::MAX as usize) {
            return Err(DNSProtoErr::EncodeTxtLengthTooLongError);
        }
        let mut result = vec![size as u8];
        result.extend_from_slice(text_bytes);
        Ok(result)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn clone_box(&self) -> Box<dyn DNSWireFrame> {
        Box::new(Self {
            text: self.text.clone(),
        })
    }
}
#[cfg(test)]
mod test {
    use crate::meta::DNSType;
    use crate::qtype::txt::DnsTypeTXT;
    use crate::qtype::DNSWireFrame;

    #[test]
    fn test_dns_type_txt_encode() {
        let non_compression_vec: Vec<u8> = vec![
            0x59, 0x76, 0x3d, 0x73, 0x70, 0x66, 0x31, 0x20, 0x69, 0x6e, 0x63, 0x6c, 0x75, 0x64,
            0x65, 0x3a, 0x73, 0x70, 0x66, 0x31, 0x2e, 0x62, 0x61, 0x69, 0x64, 0x75, 0x2e, 0x63,
            0x6f, 0x6d, 0x20, 0x69, 0x6e, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x3a, 0x73, 0x70, 0x66,
            0x32, 0x2e, 0x62, 0x61, 0x69, 0x64, 0x75, 0x2e, 0x63, 0x6f, 0x6d, 0x20, 0x69, 0x6e,
            0x63, 0x6c, 0x75, 0x64, 0x65, 0x3a, 0x73, 0x70, 0x66, 0x33, 0x2e, 0x62, 0x61, 0x69,
            0x64, 0x75, 0x2e, 0x63, 0x6f, 0x6d, 0x20, 0x61, 0x20, 0x6d, 0x78, 0x20, 0x70, 0x74,
            0x72, 0x20, 0x2d, 0x61, 0x6c, 0x6c,
        ];
        let text_record = DnsTypeTXT {
            text: "v=spf1 include:spf1.baidu.com include:spf2.baidu.com include:spf3.baidu.com a mx ptr -all".to_string(),
        };
        match text_record.encode(None) {
            Ok(text_data) => assert_eq!(text_data, non_compression_vec),
            _ => {
                assert!(false);
            }
        }

        let text = DnsTypeTXT::decode(non_compression_vec.as_slice(), None);
        assert_eq!(text.is_ok(), true);
        assert_eq!(text.unwrap(), text_record);

        assert_eq!(text_record.get_type(), DNSType::TXT);
    }
}
