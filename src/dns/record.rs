use itertools;

#[derive(Debug, PartialEq)]
pub enum ParseRRErr{
    TTLErr(u32),
    NoDefaultTTL,
    NoDefaultDomain,
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
impl Default for RecordClass {
    fn default() -> Self { RecordClass::IN }
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

impl Default for DNSType {
    fn default() -> Self { DNSType::Undefined }
}


#[derive(Debug, PartialEq, Default)]
pub struct ResourceRecord{
    name: String,
    ttl: u32,
    r_class: RecordClass,
    r_type: DNSType,
    r_data: String,

}

impl ResourceRecord{

    pub fn new(rr_str: &str, default_ttl: Option<u32>, default_domain: Option<String>) -> Result<ResourceRecord, ParseRRErr>{
        let mut s_iter =  rr_str.split_whitespace();
        let mut rr: ResourceRecord = Default::default();

        let mut is_ttl_set = false ;
        let mut is_domain_set = false;
        let mut with_default_ttl = false;
        let mut with_default_domain = false;
        let mut with_default_data = false;

        'in_break: loop{
            let item = s_iter.next();
            match item {
                Some(i) if i.to_lowercase() == "in".to_owned() => {
                    if is_ttl_set == false {
                        with_default_ttl = true;
                    }
                    if is_domain_set == false {
                        with_default_domain = true;
                    }
                    break 'in_break;
                },
                Some("@") => {
                    with_default_domain = true;
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
        let mut rdata = vec![];
        for i in s_iter{
            if i == ";"{
                break;
            }else{
                rdata.push(i);
            }
        }
        rr.r_data = itertools::join(rdata.iter()," ");
        if rr.r_data == "@".to_owned(){
            with_default_data = true;
        }

        if with_default_data == true || with_default_domain == true{
            if default_domain.is_none() {
                return Err(ParseRRErr::NoDefaultDomain)
            }else{
                let domain = default_domain.unwrap();
                if with_default_domain == true{
                    rr.name = domain.to_owned();
                }
                if with_default_data == true{
                    rr.r_data = domain.to_owned();
                }
            }
        }

        if with_default_ttl == true{
            if default_ttl.is_none(){
                return Err(ParseRRErr::NoDefaultTTL);
            }else{
                rr.ttl = default_ttl.unwrap();
            }
        }
        Ok(rr)
    }
}




#[cfg(test)]
mod test{
    use crate::dns::record::*;
    #[test]
    fn test_parse_rr_from_str(){
        let s = "mail    86400   IN  A     192.0.2.3 ; this is a comment";
        let rr: Result<ResourceRecord,ParseRRErr>  = ResourceRecord::new(s, None, None);
        assert_eq!(rr.unwrap(), ResourceRecord{
            name: "mail".to_owned(),
            ttl: 86400,
            r_class: RecordClass::IN,
            r_type: DNSType::A,
            r_data: "192.0.2.3".to_owned(),
        });

        let s = " 86400 IN  A     192.0.2.3";
        let rr: Result<ResourceRecord,ParseRRErr>  = ResourceRecord::new(s, None, Some("mail".to_owned()));
        assert_eq!(rr.unwrap(), ResourceRecord{
            name: "mail".to_owned(),
            ttl: 86400,
            r_class: RecordClass::IN,
            r_type: DNSType::A,
            r_data: "192.0.2.3".to_owned(),
        });

        let s = "  IN  A     192.0.2.3";
        let rr: Result<ResourceRecord,ParseRRErr>  = ResourceRecord::new(s, Some(1000), Some("mail".to_owned()));
        assert_eq!(rr.unwrap(), ResourceRecord{
            name: "mail".to_owned(),
            ttl: 1000,
            r_class: RecordClass::IN,
            r_type: DNSType::A,
            r_data: "192.0.2.3".to_owned(),
        });

        let s = "  IN  NS     a.dns.cn";
        let rr: Result<ResourceRecord,ParseRRErr>  = ResourceRecord::new(s, Some(1000), Some("mail".to_owned()));
        assert_eq!(rr.unwrap(), ResourceRecord{
            name: "mail".to_owned(),
            ttl: 1000,
            r_class: RecordClass::IN,
            r_type: DNSType::NS,
            r_data: "a.dns.cn".to_owned(),
        });
        //
        let s = "  IN  SOA    localhost. root.localhost.  1999010100 ( 10800 900 604800 86400 ) ";
        let rr: Result<ResourceRecord,ParseRRErr>  = ResourceRecord::new(s, Some(1000), Some("mail".to_owned()));
        assert_eq!(rr.unwrap(), ResourceRecord{
            name: "mail".to_owned(),
            ttl: 1000,
            r_class: RecordClass::IN,
            r_type: DNSType::SOA,
            r_data: "localhost. root.localhost. 1999010100 ( 10800 900 604800 86400 )".to_owned(),
        });
        //
        let s = "@  86400  IN  NS    @";
        let rr: Result<ResourceRecord,ParseRRErr>  = ResourceRecord::new(s, Some(1000), Some("mail".to_owned()));
        assert_eq!(rr.unwrap(), ResourceRecord{
            name: "mail".to_owned(),
            ttl: 86400,
            r_class: RecordClass::IN,
            r_type: DNSType::NS,
            r_data: "mail".to_owned(),
        });
    }
}