use crate::dnsname::{parse_name, DNSName};
use crate::meta::DNSType;
use crate::qtype::{CompressionType, DNSWireFrame};
use nom::bytes::complete::take_while;
use nom::character::complete::digit1;
use nom::character::complete::multispace0;
use nom::number::complete::be_u32;
use otterlib::errors::DNSProtoErr;
use std::any::Any;
use std::fmt;
use std::fmt::Formatter;
use std::str::FromStr;

#[derive(Debug, PartialEq)]
pub struct DnsTypeSOA {
    primary_name: DNSName,
    response_email: DNSName,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32,
}

pub fn is_not_space(chr: char) -> bool {
    !chr.is_whitespace()
}

named_args!(parse_soa<'a>(original: &[u8])<DnsTypeSOA>,
    do_parse!(
        primary_name: call!(parse_name, original)>>
        response_email: call!(parse_name, original) >>
        serial: be_u32>>
        refresh: be_u32>>
        retry: be_u32>>
        expire: be_u32>>
        minimum: be_u32>>
        (DnsTypeSOA{
            primary_name,
            response_email,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        }
    )
));
#[allow(clippy::too_many_arguments)]
impl DnsTypeSOA {
    pub fn new(
        primary_server: &str,
        response_email: &str,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    ) -> Result<DnsTypeSOA, DNSProtoErr> {
        Ok(DnsTypeSOA {
            primary_name: DNSName::new(primary_server, None)?,
            response_email: DNSName::new(response_email, None)?,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        })
    }
    // from_str from one line without ()
    pub fn from_str(str: &str, default_original: Option<&str>) -> Result<Self, DNSProtoErr> {
        let (rest, _) = multispace0(str)?;
        let (rest, primary) = take_while(is_not_space)(rest)?;
        let (rest, _) = multispace0(rest)?;
        let (rest, response) = take_while(is_not_space)(rest)?;
        let (rest, _) = multispace0(rest)?;
        let (rest, serial) = digit1(rest)?;
        let serial = u32::from_str(serial)?;
        let (rest, _) = multispace0(rest)?;
        let (rest, refresh) = digit1(rest)?;
        let refresh = u32::from_str(refresh)?;
        let (rest, _) = multispace0(rest)?;
        let (rest, retry) = digit1(rest)?;
        let retry = u32::from_str(retry)?;
        let (rest, _) = multispace0(rest)?;
        let (rest, expire) = digit1(rest)?;
        let expire = u32::from_str(expire)?;
        let (rest, _) = multispace0(rest)?;
        let (_, minimum) = digit1(rest)?;
        let minimum = u32::from_str(minimum)?;
        Ok(DnsTypeSOA {
            primary_name: DNSName::new(primary, default_original)?,
            response_email: DNSName::new(response, default_original)?,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        })
    }
}

impl fmt::Display for DnsTypeSOA {
    fn fmt(&self, format: &mut Formatter<'_>) -> fmt::Result {
        write!(
            format,
            "{} {} ( {} {} {} {} {} )",
            self.primary_name.to_string(),
            self.response_email.to_string(),
            self.serial,
            &self.refresh,
            self.retry,
            self.expire,
            self.minimum
        )
    }
}

impl DNSWireFrame for DnsTypeSOA {
    fn decode(data: &[u8], original: Option<&[u8]>) -> Result<Self, DNSProtoErr> {
        match parse_soa(data, original.unwrap_or(&[])) {
            Ok((_, soa)) => Ok(soa),
            Err(_err) => Err(DNSProtoErr::PacketParseError),
        }
    }

    fn get_type(&self) -> DNSType {
        DNSType::SOA
    }

    fn encode(&self, compression: CompressionType) -> Result<Vec<u8>, DNSProtoErr>
    where
        Self: Sized,
    {
        let mut data = vec![];
        match compression {
            Some((compression_map, size)) => {
                let m_name = self.primary_name.to_binary(Some((compression_map, size)));
                data.extend_from_slice(m_name.as_slice());
                let r_name = self
                    .response_email
                    .to_binary(Some((compression_map, size + m_name.len())));
                data.extend_from_slice(r_name.as_slice());
            }
            _ => {
                let m_name = self.primary_name.to_binary(None);
                data.extend_from_slice(m_name.as_slice());
                let r_name = self.response_email.to_binary(None);
                data.extend_from_slice(r_name.as_slice());
            }
        }
        data.extend_from_slice(&self.serial.to_be_bytes()[..]);
        data.extend_from_slice(&self.refresh.to_be_bytes()[..]);
        data.extend_from_slice(&self.retry.to_be_bytes()[..]);
        data.extend_from_slice(&self.expire.to_be_bytes()[..]);
        data.extend_from_slice(&self.minimum.to_be_bytes()[..]);
        Ok(data)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
#[cfg(test)]
mod test {
    use crate::dnsname::DNSName;
    use crate::label::Label;
    use crate::qtype::{DNSWireFrame, DnsTypeSOA};
    use std::collections::HashMap;
    use std::str::FromStr;

    #[test]
    fn test_parse_soa_from_str() {
        let soa = "a.dns.cn. root.cnnic.cn. 2027954656 7200 3600 2419200 21600 ";
        let dns_soa = DnsTypeSOA::from_str(soa, None);
        assert!(dns_soa.is_ok(), format!("{:?}", dns_soa.unwrap_err()));
        assert_eq!(
            dns_soa.unwrap(),
            DnsTypeSOA::new(
                "a.dns.cn.",
                "root.cnnic.cn.",
                2027954656,
                7200,
                3600,
                2419200,
                21600
            )
            .unwrap()
        );

        let err_soa = "a.dns.cn. root.cnnic.cn. 7200 3600 2419200 21600 ";
        let dns_soa = DnsTypeSOA::from_str(err_soa, None);
        assert!(dns_soa.is_err());

        let err_soa = "root.cnnic.cn. (2027954656 7200 3600 2419200 21600 )";
        let dns_soa = DnsTypeSOA::from_str(err_soa, None);
        assert!(dns_soa.is_err());
        let err_soa = "a.dns.cn. root.cnnic.cn. ( 2027954656 7200 3600 2419200 ";
        let dns_soa = DnsTypeSOA::from_str(err_soa, None);
        assert!(dns_soa.is_err());
        let err_soa = "a.dns.cn. root.cnnic.cn. 2027954656";
        let dns_soa = DnsTypeSOA::from_str(err_soa, None);
        assert!(dns_soa.is_err());
    }

    #[test]
    fn test_soa_encode() {
        let non_compression_vec: Vec<u8> = vec![
            1, 97, 12, 103, 116, 108, 100, 45, 115, 101, 114, 118, 101, 114, 115, 3, 110, 101, 116,
            0, 5, 110, 115, 116, 108, 100, 12, 118, 101, 114, 105, 115, 105, 103, 110, 45, 103,
            114, 115, 3, 99, 111, 109, 0, 96, 79, 29, 111, 0, 0, 7, 8, 0, 0, 3, 132, 0, 9, 58, 128,
            0, 1, 81, 128,
        ];
        let compression_vec: Vec<u8> = vec![
            1, 97, 12, 103, 116, 108, 100, 45, 115, 101, 114, 118, 101, 114, 115, 3, 110, 101, 116,
            0, 5, 110, 115, 116, 108, 100, 12, 118, 101, 114, 105, 115, 105, 103, 110, 45, 103,
            114, 115, 0xc0, 0x0c, 96, 79, 29, 111, 0, 0, 7, 8, 0, 0, 3, 132, 0, 9, 58, 128, 0, 1,
            81, 128,
        ];
        let soa = DnsTypeSOA {
            primary_name: DNSName::new("a.gtld-servers.net.", None).unwrap(),
            response_email: DNSName::new("nstld.verisign-grs.com.", None).unwrap(),
            serial: 1615797615,
            refresh: 1800,
            retry: 900,
            expire: 604800,
            minimum: 86400,
        };
        match soa.encode(None) {
            Ok(v) => {
                assert_eq!(v, non_compression_vec, "soa encode not equal")
            }
            Err(err) => {
                assert!(false, format!("error: {:?}", err));
            }
        }
        let mut compression_map = HashMap::new();
        compression_map.insert(vec![Label::from_str("com").unwrap()], 12);
        match soa.encode(Some((&mut compression_map, 0))) {
            Ok(v) => {
                // println!("{:x?}", v);
                assert_eq!(v, compression_vec, "soa encode not equal")
            }
            Err(err) => {
                assert!(false, format!("error: {:?}", err));
            }
        }
    }
}
