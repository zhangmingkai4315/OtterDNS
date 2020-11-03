use crate::dns::domain::{is_fqdn, valid_domain};

#[derive(Debug, PartialEq, Clone)]
pub enum ParseRRErr {
    ValidDomainErr(String),
    ValidTypeErr(String),
    NoDefaultTTL,
    NoDefaultDomain,
    NoDomainType,
    NoOriginDomain,
    GeneralFail(String),
    EmptyStrErr,
    UnknownErr,

}

/// https://tools.ietf.org/html/rfc1035#section-3.2.4
/// specify the class of the dns record data
#[derive(Debug, PartialEq, Copy, Clone)]
#[repr(u16)]
pub enum RecordClass {
    Undefined = 0,
    IN = 1,
    // 1 the Internet
    CS,
    // 2 the CSNET class
    CH,
    // 3 the CHAOS class
    HS,      // 4 Hesiod
}

impl Default for RecordClass {
    fn default() -> Self { RecordClass::IN }
}


#[derive(Debug, PartialEq, Copy, Clone)]
#[repr(u16)]
#[derive(EnumString)]
pub enum DNSType {
    Undefined = 0,
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    HINFO = 13,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    // Rfc3596
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
pub struct ResourceRecord {
    name: String,
    ttl: u32,
    r_class: RecordClass,
    r_type: DNSType,
    r_data: String,
}

impl ResourceRecord {
    pub fn new(rr_str: &str,
               default_ttl: Option<u32>,
               default_class: Option<RecordClass>,
               default_domain: Option<&str>,
               default_origin: Option<&str>,
    )
               -> Result<ResourceRecord, ParseRRErr> {
        let mut is_ttl_set = false;
        let mut is_domain_set = false;
        let mut is_class_set = false;
        let mut with_default_ttl = false;
        let mut with_default_domain = false;
        let default_record_class = {
            if default_class.is_none(){
                RecordClass::IN
            }else{
                default_class.unwrap()
            }
        };
        // if begin with a empty or \t then using default domain
        if rr_str.starts_with(|s| s == ' ' || s == '\t') {
            with_default_domain = true;
            is_domain_set = true;
        }
        let mut name: &str = "";
        let mut r_type = DNSType::Undefined;
        let mut r_data = String::new();
        let mut r_class = default_record_class;
        let mut ttl = 0;

        // split using whitespace
        let mut s_iter = rr_str.split_whitespace();
        let token = s_iter.next();
        if token.is_none() {
            return Err(ParseRRErr::EmptyStrErr);
        }
        let mut token = token.unwrap();
        // if already set ,then parse for ttl, class or type.
        // otherwise check if include @ replace with default domain later
        if is_domain_set == false {
            if token.eq("@") {
                // domain exist with @
                with_default_domain = true;
            } else {
                // domain exist and been set with str
                name = token;
            }
            is_domain_set = true;
            // get a new token
            match s_iter.next() {
                Some(t) => token = t,
                // next required is domain type but got nothing
                _ => return Err(ParseRRErr::NoDomainType)
            }
        }

        if with_default_domain == true {
            if let Some(default_domain_str) = default_domain {
                name = default_domain_str;
            } else {
                return Err(ParseRRErr::NoDefaultDomain);
            }
        }
        let mut domain_fqdn = String::new();
        if is_fqdn(name) != true{
            if let Some(origin) = default_origin{
                domain_fqdn = format!("{}.{}", name.to_owned() ,origin.to_owned());
            }else{
                return Err(ParseRRErr::NoOriginDomain)
            }
        }else{
            domain_fqdn = name.to_owned();
        }
        if valid_domain(name) == false{
            return Err(ParseRRErr::ValidDomainErr(format!("domain: {} not valid", name)));
        }
        // token must be ttl or class or type
        // after this code, at least we don't need care about ttl.
        if let Ok(t) = token.parse::<u32>() {
            is_ttl_set = true;
            ttl = t;
        }
        if token == "IN" || token == "in" {
            is_class_set = true;
            r_class = RecordClass::IN;
        }else if token == "CH" || token == "ch"{
            is_class_set = true;
            r_class = RecordClass::CH;
        }

        if is_ttl_set == false{
            is_ttl_set = true;
            with_default_ttl = true;
        }

        if is_class_set == true{
            is_ttl_set = true;
            with_default_ttl = true;
        }

        let rtype: &str;

        // there are two option for is_class_set == false
        // 1. token is dns type
        // 2. token is ttl when is_ttl_set = true and
        if is_class_set == false {

            if is_ttl_set == true{
                // current token must be ttl, get a new token
                if let Some(token) = s_iter.next() {
                    // maybe class or type
                    if token == "IN" || token == "in" {
                        is_class_set = true;
                        r_class = RecordClass::IN;
                        // get a new type
                        if let Some(token) = s_iter.next() {
                            // token is domain type now
                            rtype = token.as_ref();
                        } else {
                            return Err(ParseRRErr::NoDomainType);
                        }
                    }else if token == "CH" || token == "ch"{
                        is_class_set = true;
                        r_class = RecordClass::CH;
                        // get a new type
                        if let Some(token) = s_iter.next() {
                            // token is domain type now
                            rtype = token.as_ref();
                        } else {
                            return Err(ParseRRErr::NoDomainType);
                        }
                    }else{
                        // current token is type
                        rtype = token.as_ref();
                    }
                }else{
                    return Err(ParseRRErr::NoDomainType);
                }
            }else{
                // this token is domain type
                rtype = token.as_ref();
            }

        } else {
            // class is been set , so get a new token must be dns type
            if let Some(token) = s_iter.next() {
                // token is domain type now
                rtype = token.as_ref();
            } else {
                return Err(ParseRRErr::NoDomainType);
            }
        }

        // for now we only care about all required attribute
        // : rtype rdata
        if let Ok(rtype) = rtype.to_uppercase().parse::<DNSType>() {
            r_type = rtype;
        } else {
            return Err(ParseRRErr::ValidTypeErr(format!("{} can not be recognised", rtype)));
        }
        // rdata may include ; comment should be ignored(should remove before feed to RecordResource)
        let mut rest_rdata_vec = vec![];
        let mut begin_item_processed = false;

        while let Some(v) = s_iter.next() {
            if begin_item_processed == false && v == "@" {
                let mut fqdn = String::new();
                if let Some(default_domain_str) = default_domain {
                    // default_domain exist but may not be fqdn , we also need to get orgin
                    if is_fqdn(default_domain_str) != true{
                        if let Some(orign) = default_origin{
                            fqdn = format!("{}.{}", default_domain_str,orign);
                            rest_rdata_vec.push(fqdn);
                        } else {
                            return Err(ParseRRErr::NoOriginDomain);
                        }
                    }else{
                        rest_rdata_vec.push(default_domain_str.to_owned())
                    }
                } else {
                    return Err(ParseRRErr::NoDefaultDomain);
                }
                begin_item_processed = true;
            } else {
                if v.starts_with(";") {
                    break;
                }
                rest_rdata_vec.push(v.to_owned());
            }
        }
        r_data = rest_rdata_vec.join(" ");

        // rr.r_data = s_iter.flat_map(|s| s.chars()).collect();
        if with_default_ttl == true {
            if let Some(t) = default_ttl {
                ttl = t;
            } else {
                return Err(ParseRRErr::NoDefaultTTL);
            }
        }

        Ok(ResourceRecord {
            name: domain_fqdn,
            ttl: ttl,
            r_class: r_class,
            r_type: r_type,
            r_data: r_data.to_owned(),
        })
    }
}


#[cfg(test)]
mod test {
    use crate::dns::record::*;

    #[test]
    fn test_parse_rr_from_str() {
        let s = "mail.    86400   IN  A     192.0.2.3 ; this is a comment";
        let rr: Result<ResourceRecord, ParseRRErr> = ResourceRecord::new(
            s, None, None,None,None,
        );
        assert_eq!(rr.unwrap(), ResourceRecord {
            name: "mail.".to_owned(),
            ttl: 86400,
            r_class: RecordClass::IN,
            r_type: DNSType::A,
            r_data: "192.0.2.3".to_owned(),
        });
        let s = "mail    86400   IN  A     192.0.2.3 ; this is a comment";
        let rr: Result<ResourceRecord, ParseRRErr> = ResourceRecord::new(
            s, None, None,None,Some("cnnic.cn"),
        );
        assert_eq!(rr.unwrap(), ResourceRecord {
            name: "mail.cnnic.cn".to_owned(),
            ttl: 86400,
            r_class: RecordClass::IN,
            r_type: DNSType::A,
            r_data: "192.0.2.3".to_owned(),
        });

        let s = "mail.    86400   IN  A     192.0.2.3 ; this is a comment";
        let rr: Result<ResourceRecord, ParseRRErr> = ResourceRecord::new(
            s, None, None,None,Some("cnnic.cn"),
        );
        assert_eq!(rr.unwrap(), ResourceRecord {
            name: "mail.".to_owned(),
            ttl: 86400,
            r_class: RecordClass::IN,
            r_type: DNSType::A,
            r_data: "192.0.2.3".to_owned(),
        });

        let s = " 86400 IN  A     192.0.2.3";
        let rr: Result<ResourceRecord, ParseRRErr> = ResourceRecord::new(
            s, Some(1000),None, Some("mail."),None,
        );
        assert_eq!(rr.unwrap(), ResourceRecord {
            name: "mail.".to_owned(),
            ttl: 86400,
            r_class: RecordClass::IN,
            r_type: DNSType::A,
            r_data: "192.0.2.3".to_owned(),
        });

        let s = "  IN  A     192.0.2.3";
        let rr: Result<ResourceRecord, ParseRRErr> = ResourceRecord::new(
            s, Some(1000), None, Some("mail."),None,
        );
        assert_eq!(rr.unwrap(), ResourceRecord {
            name: "mail.".to_owned(),
            ttl: 1000,
            r_class: RecordClass::IN,
            r_type: DNSType::A,
            r_data: "192.0.2.3".to_owned(),
        });

        let s = "  IN  NS     a.dns.cn";
        let rr: Result<ResourceRecord, ParseRRErr> = ResourceRecord::new(
            s, Some(1000), None, Some("mail."),None,
        );
        assert_eq!(rr.unwrap(), ResourceRecord {
            name: "mail.".to_owned(),
            ttl: 1000,
            r_class: RecordClass::IN,
            r_type: DNSType::NS,
            r_data: "a.dns.cn".to_owned(),
        });
        //
        let s = "  IN  SOA    localhost. root.localhost.  1999010100 ( 10800 900 604800 86400 ) ";
        let rr: Result<ResourceRecord, ParseRRErr> = ResourceRecord::new(
            s, Some(1000), None, Some("mail"),Some("google.com."),
        );
        assert_eq!(rr.unwrap(), ResourceRecord {
            name: "mail.google.com.".to_owned(),
            ttl: 1000,
            r_class: RecordClass::IN,
            r_type: DNSType::SOA,
            r_data: "localhost. root.localhost. 1999010100 ( 10800 900 604800 86400 )".to_owned(),
        });

        let s = "in.    86400   IN  A     192.0.2.3 ; this is a comment";
        let rr: Result<ResourceRecord, ParseRRErr> = ResourceRecord::new(
            s, None, None, None,None,
        );
        assert_eq!(rr.unwrap(), ResourceRecord {
            name: "in.".to_owned(),
            ttl: 86400,
            r_class: RecordClass::IN,
            r_type: DNSType::A,
            r_data: "192.0.2.3".to_owned(),
        });
        let s = "in    86400   IN  A     192.0.2.3 ; this is a comment";
        let rr: Result<ResourceRecord, ParseRRErr> = ResourceRecord::new(
            s, None, None, Some("default"),Some("google.com."),
        );
        assert_eq!(rr.unwrap(), ResourceRecord {
            name: "in.google.com.".to_owned(),
            ttl: 86400,
            r_class: RecordClass::IN,
            r_type: DNSType::A,
            r_data: "192.0.2.3".to_owned(),
        });

        let s = "in    86400   CH  A     192.0.2.3 ; this is a comment";
        let rr: Result<ResourceRecord, ParseRRErr> = ResourceRecord::new(
            s, None, None, Some("default"),Some("google.com."),
        );
        assert_eq!(rr.unwrap(), ResourceRecord {
            name: "in.google.com.".to_owned(),
            ttl: 86400,
            r_class: RecordClass::CH,
            r_type: DNSType::A,
            r_data: "192.0.2.3".to_owned(),
        });

        let s = "  86400   IN  A     192.0.2.3 ; this is a comment";
        let rr: Result<ResourceRecord, ParseRRErr> = ResourceRecord::new(
            s, None, None, Some("default"),Some("google.com."),
        );
        assert_eq!(rr.unwrap(), ResourceRecord {
            name: "default.google.com.".to_owned(),
            ttl: 86400,
            r_class: RecordClass::IN,
            r_type: DNSType::A,
            r_data: "192.0.2.3".to_owned(),
        });
        //
        let s = "@  86400  IN  NS    @";
        let rr: Result<ResourceRecord, ParseRRErr> = ResourceRecord::new(
            s, Some(1000), None, Some("mail."),None,
        );
        assert_eq!(rr.unwrap(), ResourceRecord {
            name: "mail.".to_owned(),
            ttl: 86400,
            r_class: RecordClass::IN,
            r_type: DNSType::NS,
            r_data: "mail.".to_owned(),
        });

        let s = "@  86400  IN  NS    @";
        let rr: Result<ResourceRecord, ParseRRErr> = ResourceRecord::new(
            s, Some(1000), None, Some("mail."),Some("google.com."),
        );
        assert_eq!(rr.unwrap(), ResourceRecord {
            name: "mail.".to_owned(),
            ttl: 86400,
            r_class: RecordClass::IN,
            r_type: DNSType::NS,
            r_data: "mail.".to_owned(),
        });

        let s = "@  86400  IN  NS    @";
        let rr: Result<ResourceRecord, ParseRRErr> = ResourceRecord::new(
            s, Some(1000), None, Some("mail"),Some("google.com."),
        );
        assert_eq!(rr.unwrap(), ResourceRecord {
            name: "mail.google.com.".to_owned(),
            ttl: 86400,
            r_class: RecordClass::IN,
            r_type: DNSType::NS,
            r_data: "mail.google.com.".to_owned(),
        });

        let s = "@  IN  NS  @";
        let rr: Result<ResourceRecord, ParseRRErr> = ResourceRecord::new(
            s, Some(1000), None, None,None,
        );
        assert_eq!(rr.is_err(), true);

        let rr: Result<ResourceRecord, ParseRRErr> = ResourceRecord::new(
            s, Some(1000), None, None,None,
        );
        assert_eq!(rr.unwrap_err(), ParseRRErr::NoDefaultDomain);

        let rr: Result<ResourceRecord, ParseRRErr> = ResourceRecord::new(
            s, None, None, Some("mail"),None,
        );
        assert_eq!(rr.is_err(), true);

        let rr: Result<ResourceRecord, ParseRRErr> = ResourceRecord::new(
            s, None, None, Some("mail"), None,
        );
        assert_eq!(rr.unwrap_err(), ParseRRErr::NoOriginDomain);
    }
}