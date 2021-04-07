use crate::dnsname::{parse_name, DNSName};
use crate::meta::DNSType;
use crate::qtype::soa::is_not_space;
use crate::qtype::{CompressionType, DNSWireFrame};
use nom::bytes::complete::take_while;
use nom::character::complete::digit1;
use nom::character::complete::multispace0;
use nom::number::complete::be_u16;
use otterlib::errors::{DNSProtoErr, ParseZoneDataErr};
use std::any::Any;
use std::fmt;
use std::fmt::Formatter;
use std::str::FromStr;

// https://tools.ietf.org/html/rfc2782
// # _service._proto.name.  TTL   class SRV priority weight port target.
// _sip._tcp.example.com.   86400 IN    SRV 10       60     5060 bigbox.example.com.
// _sip._tcp.example.com.   86400 IN    SRV 10       20     5060 smallbox1.example.com.
// _sip._tcp.example.com.   86400 IN    SRV 10       20     5060 smallbox2.example.com.
// _sip._tcp.example.com.   86400 IN    SRV 20       0      5060 backupbox.example.com.

#[derive(Debug, PartialEq)]
pub struct DnsTypeSRV {
    priority: u16,
    weight: u16,
    port: u16,
    target: DNSName,
}

named_args!(parse_srv<'a>(original: &[u8])<DnsTypeSRV>,
    do_parse!(
        priority: be_u16>>
        weight: be_u16>>
        port: be_u16>>
        target: call!(parse_name, original)>>

        (DnsTypeSRV{
            priority,
            weight,
            port,
            target,
        }
    )
));
#[allow(clippy::too_many_arguments)]
impl DnsTypeSRV {
    pub fn new(
        priority: u16,
        weight: u16,
        port: u16,
        target: &str,
    ) -> Result<DnsTypeSRV, DNSProtoErr> {
        Ok(DnsTypeSRV {
            priority,
            weight,
            port,
            target: DNSName::new(target, None)?,
        })
    }
    pub fn from_str(str: &str, default_original: Option<&str>) -> Result<Self, ParseZoneDataErr> {
        let (rest, _) = multispace0(str)?;
        let (rest, priority) = digit1(rest)?;
        let priority = u16::from_str(priority)?;
        let (rest, _) = multispace0(rest)?;
        let (rest, weight) = digit1(rest)?;
        let weight = u16::from_str(weight)?;
        let (rest, _) = multispace0(rest)?;
        let (rest, port) = digit1(rest)?;
        let port = u16::from_str(port)?;
        let (rest, _) = multispace0(rest)?;
        let (_, target) = take_while(is_not_space)(rest)?;

        Ok(DnsTypeSRV {
            priority,
            weight,
            port,
            target: DNSName::new(target, default_original)?,
        })
    }
}

impl fmt::Display for DnsTypeSRV {
    fn fmt(&self, format: &mut Formatter<'_>) -> fmt::Result {
        write!(
            format,
            "{} {} {} {}",
            self.priority,
            self.weight,
            self.port,
            self.target.to_string(),
        )
    }
}

impl DNSWireFrame for DnsTypeSRV {
    fn decode(data: &[u8], original: Option<&[u8]>) -> Result<Self, DNSProtoErr> {
        match parse_srv(data, original.unwrap_or(&[])) {
            Ok((_, soa)) => Ok(soa),
            Err(_err) => Err(DNSProtoErr::PacketParseError),
        }
    }

    fn get_type(&self) -> DNSType {
        DNSType::SRV
    }

    fn encode(&self, compression: CompressionType) -> Result<Vec<u8>, DNSProtoErr>
    where
        Self: Sized,
    {
        let mut data = vec![];
        data.extend_from_slice(&self.priority.to_be_bytes()[..]);
        data.extend_from_slice(&self.weight.to_be_bytes()[..]);
        data.extend_from_slice(&self.port.to_be_bytes()[..]);
        match compression {
            Some((compression_map, size)) => {
                let m_name = self.target.to_binary(Some((compression_map, size)));
                data.extend_from_slice(m_name.as_slice());
            }
            _ => {
                let m_name = self.target.to_binary(None);
                data.extend_from_slice(m_name.as_slice());
            }
        }
        Ok(data)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod test {
    use crate::qtype::srv::DnsTypeSRV;
    use crate::qtype::DNSWireFrame;
    use std::str::FromStr;

    #[test]
    fn test_srv_decode() {
        let srv_bin = vec![
            0x00, 0x0a, 0x00, 0x01, 0x1f, 0x90, 0x03, 0x66, 0x74, 0x70, 0x0c, 0x7a, 0x68, 0x61,
            0x6e, 0x67, 0x6d, 0x69, 0x6e, 0x67, 0x6b, 0x61, 0x69, 0x02, 0x63, 0x6e, 0x00,
        ];
        let srv_record = DnsTypeSRV::from_str("10 1 8080 ftp.zhangmingkai.cn.", None);
        assert_eq!(srv_record.is_ok(), true);
        let srv_record = srv_record.unwrap();
        let from_bin = DnsTypeSRV::decode(srv_bin.as_slice(), None);
        assert_eq!(from_bin.is_ok(), true);
        // println!("{:?}", from_bin.unwrap_err());
        let from_bin = from_bin.unwrap();
        assert_eq!(from_bin, srv_record)
    }

    #[test]
    fn test_srv_encode() {
        let srv_bin = vec![
            0x00, 0x0a, 0x00, 0x01, 0x1f, 0x90, 0x03, 0x66, 0x74, 0x70, 0x0c, 0x7a, 0x68, 0x61,
            0x6e, 0x67, 0x6d, 0x69, 0x6e, 0x67, 0x6b, 0x61, 0x69, 0x02, 0x63, 0x6e, 0x00,
        ];
        let srv_record = DnsTypeSRV::from_str("10 1 8080 ftp.zhangmingkai.cn.", None);
        assert_eq!(srv_record.is_ok(), true);
        let srv_record = srv_record.unwrap();
        let encoded = srv_record.encode(None);
        assert_eq!(encoded.is_ok(), true);
        assert_eq!(encoded.unwrap(), srv_bin);
    }
}
