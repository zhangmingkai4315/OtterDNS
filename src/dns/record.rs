use std::str::FromStr;
use itertools;

#[derive(Debug, PartialEq)]
pub enum ParseRRErr{
    TTLErr(u32),
    TypeErr(String),
    ClassErr(String),
    EmptyStrErr,
    GeneralFail(String),
}

/// https://tools.ietf.org/html/rfc1035#section-3.2.4
/// specify the class of the dns record data
#[derive(Debug, PartialEq)]
#[repr(u16)]
pub enum RecordClass{
    IN = 1,  // 1 the Internet
    CS,      // 2 the CSNET class
    CH,      // 3 the CHAOS class
    HS,      // 4 Hesiod
}

#[derive(Debug, PartialEq)]
#[repr(u16)]
#[derive(EnumString)]
pub enum DNSType{
    Undefined = 0,
    A = 1 ,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    HINFO = 13,
    MX = 15,
    TXT = 16,
    AAAA = 28,   // Rfc3596
    SRV = 33,
    DS = 43,
    RRSIG = 46,
    NSEC = 47,
    DNSKEY = 48,
    NSEC3 = 50,
    NSEC3PARAM = 51,
    AXFR = 252,
    Any = 255,  // Rfc1035: return all records of all types known to the dns server
}


#[derive(Debug, PartialEq)]
pub struct ResourceRecord{
    name: String,
    ttl: u32,
    r_class: RecordClass,
    r_type: DNSType,
    r_data: String,
    with_default_ttl: bool,
    with_default_domain: bool,
}

impl ResourceRecord{
    pub fn new(rr_str: String) -> Result<ResourceRecord, ParseRRErr>{
        rr_str.parse()
    }
    pub fn default()-> ResourceRecord{
        ResourceRecord{
            name: "".to_owned(),
            ttl: 0,
            r_class: RecordClass::IN,
            r_type: DNSType::Undefined,
            r_data: "".to_owned(),
            with_default_ttl: false,
            with_default_domain: false,
        }
    }
}



impl FromStr for ResourceRecord{
    type Err = ParseRRErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut s_iter =  s.split_whitespace();
        let mut rr = ResourceRecord::default();
        let mut is_ttl_set = false ;
        let mut is_domain_set = false;
        'in_break: loop{
            let item = s_iter.next();
            match item {
                Some(i) if i.to_lowercase() == "in" => {
                    if is_ttl_set == false {
                        rr.with_default_ttl = true;
                    }
                    if is_domain_set == false {
                        rr.with_default_domain = true;
                    }
                    break 'in_break;
                },
                Some("@") => {
                    rr.with_default_domain = true;
                    is_domain_set = true;
                },
                Some(s) => {
                    if let Ok(ttl)= s.parse::<u32>(){
                        rr.ttl = ttl;
                        is_ttl_set = true;
                    }else{
                        rr.name = item.unwrap().to_owned();
                        is_domain_set = true;
                    }
                },
                _ => {
                    break 'in_break;
                }
            }
        }

        if let Some(dtype) = s_iter.next(){
            let dnstype =  dtype.to_uppercase().parse();
            if dnstype.is_ok(){
                rr.r_type = dnstype.unwrap();
            }else{
                return Err(ParseRRErr::TypeErr(format!("{} can not be recognised", dtype)));
            }
        }

        // rr.r_data = s_iter.flat_map(|s| s.chars()).collect();
        rr.r_data = itertools::join(s_iter," ");
        Ok(rr)
    }
}



#[cfg(test)]
mod test{
    use crate::dns::record::*;
    #[test]
    fn test_parse_rr_from_str(){
        let s = "mail    86400   IN  A     192.0.2.3";
        let rr: Result<ResourceRecord,ParseRRErr>  = s.parse();
        assert_eq!(rr.unwrap(), ResourceRecord{
            name: "mail".to_owned(),
            ttl: 86400,
            r_class: RecordClass::IN,
            r_type: DNSType::A,
            r_data: "192.0.2.3".to_owned(),
            with_default_ttl: false,
            with_default_domain: false,
        });
    }
}