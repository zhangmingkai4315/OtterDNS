use crate::errors::*;
use crate::meta::{DNSClass, DNSType};
use crate::utils::{is_fqdn, valid_domain};
#[derive(Debug, PartialEq, Default)]
pub struct ResourceRecord {
    pub name: String,
    pub ttl: u32,
    pub r_class: DNSClass,
    pub r_type: DNSType,
    pub r_data: String,
}

impl ResourceRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rr_str: &str,
        default_ttl: Option<u32>,
        default_class: Option<DNSClass>,
        default_domain: Option<&str>,
        default_origin: Option<&str>,
    ) -> Result<ResourceRecord, ParseZoneDataErr> {
        let mut is_ttl_set;
        let is_domain_set;
        let is_class_set;
        let mut with_default_ttl = false;
        let mut with_default_domain = false;
        let default_record_class = default_class.unwrap_or(DNSClass::IN);
        // if begin with a empty or \t then using default domain
        if rr_str.starts_with(|s| s == ' ' || s == '\t') {
            with_default_domain = true;
            is_domain_set = true;
        } else {
            is_domain_set = false;
        }
        let mut name: &str = "";
        let r_type: DNSType;
        let r_data: String;
        let mut r_class = default_record_class;
        let mut ttl = 0;

        // split using whitespace
        let mut s_iter = rr_str.split_whitespace();
        let token = s_iter.next();
        if token.is_none() {
            return Err(ParseZoneDataErr::EmptyStrErr);
        }
        let mut token = token.unwrap();
        // if already set ,then parse for ttl, class or type.
        // otherwise check if include @ replace with default domain later
        if !is_domain_set {
            if token.eq("@") {
                // domain exist with @
                with_default_domain = true;
            } else {
                // domain exist and been set with str
                name = token;
            }
            // get a new token
            match s_iter.next() {
                Some(token_str) => token = token_str,
                // next required is domain type but got nothing
                _ => return Err(ParseZoneDataErr::NoDomainType),
            }
        }

        if with_default_domain {
            if let Some(default_domain_str) = default_domain {
                name = default_domain_str;
            } else {
                return Err(ParseZoneDataErr::NoDefaultDomain);
            }
        }
        let domain_fqdn: String;
        if !is_fqdn(name) {
            if let Some(origin) = default_origin {
                domain_fqdn = format!("{}.{}", name.to_owned(), origin.to_owned());
            } else {
                return Err(ParseZoneDataErr::NoOriginDomain);
            }
        } else {
            domain_fqdn = name.to_owned();
        }
        if !valid_domain(name) {
            return Err(ParseZoneDataErr::ValidDomainErr(name.to_owned()));
        }
        // token must be ttl or class or type
        // after this code, at least we don't need care about ttl.
        if let Ok(t) = token.parse::<u32>() {
            is_ttl_set = true;
            ttl = t;
        } else {
            is_ttl_set = false;
        }
        if token == "IN" || token == "in" {
            is_class_set = true;
            r_class = DNSClass::IN;
        } else if token == "CH" || token == "ch" {
            is_class_set = true;
            r_class = DNSClass::CH;
        } else {
            is_class_set = false;
        }

        if !is_ttl_set {
            is_ttl_set = true;
            with_default_ttl = true;
        }

        if is_class_set {
            is_ttl_set = true;
            with_default_ttl = true;
        }

        let rtype: &str;

        // there are two options
        // 1. token is ttl when is_ttl_set = true and with_default_ttl = false
        // 2. token is dns type
        if !is_class_set {
            if is_ttl_set && !with_default_ttl {
                // current token must be ttl, get a new token
                if let Some(token) = s_iter.next() {
                    // maybe class or type
                    if token == "IN" || token == "in" {
                        r_class = DNSClass::IN;
                        // get a new type
                        if let Some(token) = s_iter.next() {
                            // token is domain type now
                            rtype = token;
                        } else {
                            return Err(ParseZoneDataErr::NoDomainType);
                        }
                    } else if token == "CH" || token == "ch" {
                        r_class = DNSClass::CH;
                        // get a new type
                        if let Some(token) = s_iter.next() {
                            // token is domain type now
                            rtype = token;
                        } else {
                            return Err(ParseZoneDataErr::NoDomainType);
                        }
                    } else {
                        // current token is type
                        rtype = token;
                    }
                } else {
                    return Err(ParseZoneDataErr::NoDomainType);
                }
            } else {
                // this token is domain type
                rtype = token;
            }
        } else {
            // class is been set , so get a new token must be dns type
            if let Some(token) = s_iter.next() {
                // token is domain type now
                rtype = token;
            } else {
                return Err(ParseZoneDataErr::NoDomainType);
            }
        }

        // for now we only care about all required attribute
        // : rtype rdata
        if let Ok(rtype) = rtype.to_uppercase().parse::<DNSType>() {
            r_type = rtype;
        } else {
            return Err(ParseZoneDataErr::ValidTypeErr(format!(
                "{} can not be recognised",
                rtype
            )));
        }
        // rdata may include ; comment should be ignored(should remove before feed to RecordResource)
        let mut rest_rdata_vec = vec![];
        let mut begin_item_processed = false;

        for v in s_iter {
            if !begin_item_processed && v == "@" {
                let fqdn: String;
                if let Some(default_domain_str) = default_domain {
                    // default_domain exist but may not be fqdn , we also need to get orgin
                    if !is_fqdn(default_domain_str) {
                        if let Some(orign) = default_origin {
                            fqdn = format!("{}.{}", default_domain_str, orign);
                            rest_rdata_vec.push(fqdn);
                        } else {
                            return Err(ParseZoneDataErr::NoOriginDomain);
                        }
                    } else {
                        rest_rdata_vec.push(default_domain_str.to_owned())
                    }
                } else {
                    return Err(ParseZoneDataErr::NoDefaultDomain);
                }
                begin_item_processed = true;
            } else {
                if v.starts_with(';') {
                    break;
                }
                rest_rdata_vec.push(v.to_owned());
            }
        }
        r_data = rest_rdata_vec.join(" ");

        // rr.r_data = s_iter.flat_map(|s| s.chars()).collect();
        if with_default_ttl {
            if let Some(t) = default_ttl {
                ttl = t;
            } else {
                return Err(ParseZoneDataErr::NoDefaultTTL);
            }
        }

        Ok(ResourceRecord {
            name: domain_fqdn,
            ttl,
            r_class,
            r_type,
            r_data,
        })
    }
}

#[test]
fn test_parse_rr_from_str() {
    let s = "mail.    86400   IN  A     192.0.2.3 ; this is a comment";
    let rr: Result<ResourceRecord, ParseZoneDataErr> =
        ResourceRecord::new(s, None, None, None, None);
    assert_eq!(
        rr.unwrap(),
        ResourceRecord {
            name: "mail.".to_owned(),
            ttl: 86400,
            r_class: DNSClass::IN,
            r_type: DNSType::A,
            r_data: "192.0.2.3".to_owned(),
        }
    );
    let s = "mail    86400   IN  A     192.0.2.3 ; this is a comment";
    let rr: Result<ResourceRecord, ParseZoneDataErr> =
        ResourceRecord::new(s, None, None, None, Some("cnnic.cn"));
    assert_eq!(
        rr.unwrap(),
        ResourceRecord {
            name: "mail.cnnic.cn".to_owned(),
            ttl: 86400,
            r_class: DNSClass::IN,
            r_type: DNSType::A,
            r_data: "192.0.2.3".to_owned(),
        }
    );

    let s = "mail.    86400   IN  A     192.0.2.3 ; this is a comment";
    let rr: Result<ResourceRecord, ParseZoneDataErr> =
        ResourceRecord::new(s, None, None, None, Some("cnnic.cn"));
    assert_eq!(
        rr.unwrap(),
        ResourceRecord {
            name: "mail.".to_owned(),
            ttl: 86400,
            r_class: DNSClass::IN,
            r_type: DNSType::A,
            r_data: "192.0.2.3".to_owned(),
        }
    );

    let s = " 86400 IN  A     192.0.2.3";
    let rr: Result<ResourceRecord, ParseZoneDataErr> =
        ResourceRecord::new(s, Some(1000), None, Some("mail."), None);
    assert_eq!(
        rr.unwrap(),
        ResourceRecord {
            name: "mail.".to_owned(),
            ttl: 86400,
            r_class: DNSClass::IN,
            r_type: DNSType::A,
            r_data: "192.0.2.3".to_owned(),
        }
    );

    let s = "  IN  A     192.0.2.3";
    let rr: Result<ResourceRecord, ParseZoneDataErr> =
        ResourceRecord::new(s, Some(1000), None, Some("mail."), None);
    assert_eq!(
        rr.unwrap(),
        ResourceRecord {
            name: "mail.".to_owned(),
            ttl: 1000,
            r_class: DNSClass::IN,
            r_type: DNSType::A,
            r_data: "192.0.2.3".to_owned(),
        }
    );

    let s = "  IN  NS     a.dns.cn";
    let rr: Result<ResourceRecord, ParseZoneDataErr> =
        ResourceRecord::new(s, Some(1000), None, Some("mail."), None);
    assert_eq!(
        rr.unwrap(),
        ResourceRecord {
            name: "mail.".to_owned(),
            ttl: 1000,
            r_class: DNSClass::IN,
            r_type: DNSType::NS,
            r_data: "a.dns.cn".to_owned(),
        }
    );
    //
    let s = "  IN  SOA    localhost. root.localhost.  1999010100 ( 10800 900 604800 86400 ) ";
    let rr: Result<ResourceRecord, ParseZoneDataErr> =
        ResourceRecord::new(s, Some(1000), None, Some("mail"), Some("google.com."));
    assert_eq!(
        rr.unwrap(),
        ResourceRecord {
            name: "mail.google.com.".to_owned(),
            ttl: 1000,
            r_class: DNSClass::IN,
            r_type: DNSType::SOA,
            r_data: "localhost. root.localhost. 1999010100 ( 10800 900 604800 86400 )".to_owned(),
        }
    );

    let s = "in.    86400   IN  A     192.0.2.3 ; this is a comment";
    let rr: Result<ResourceRecord, ParseZoneDataErr> =
        ResourceRecord::new(s, None, None, None, None);
    assert_eq!(
        rr.unwrap(),
        ResourceRecord {
            name: "in.".to_owned(),
            ttl: 86400,
            r_class: DNSClass::IN,
            r_type: DNSType::A,
            r_data: "192.0.2.3".to_owned(),
        }
    );
    let s = "in    86400   IN  A     192.0.2.3 ; this is a comment";
    let rr: Result<ResourceRecord, ParseZoneDataErr> =
        ResourceRecord::new(s, None, None, Some("default"), Some("google.com."));
    assert_eq!(
        rr.unwrap(),
        ResourceRecord {
            name: "in.google.com.".to_owned(),
            ttl: 86400,
            r_class: DNSClass::IN,
            r_type: DNSType::A,
            r_data: "192.0.2.3".to_owned(),
        }
    );

    let s = "in    86400   CH  A     192.0.2.3 ; this is a comment";
    let rr: Result<ResourceRecord, ParseZoneDataErr> =
        ResourceRecord::new(s, None, None, Some("default"), Some("google.com."));
    assert_eq!(
        rr.unwrap(),
        ResourceRecord {
            name: "in.google.com.".to_owned(),
            ttl: 86400,
            r_class: DNSClass::CH,
            r_type: DNSType::A,
            r_data: "192.0.2.3".to_owned(),
        }
    );

    let s = "  86400   IN  A     192.0.2.3 ; this is a comment";
    let rr: Result<ResourceRecord, ParseZoneDataErr> =
        ResourceRecord::new(s, None, None, Some("default"), Some("google.com."));
    assert_eq!(
        rr.unwrap(),
        ResourceRecord {
            name: "default.google.com.".to_owned(),
            ttl: 86400,
            r_class: DNSClass::IN,
            r_type: DNSType::A,
            r_data: "192.0.2.3".to_owned(),
        }
    );
    //
    let s = "@  86400  IN  NS    @";
    let rr: Result<ResourceRecord, ParseZoneDataErr> =
        ResourceRecord::new(s, Some(1000), None, Some("mail."), None);
    assert_eq!(
        rr.unwrap(),
        ResourceRecord {
            name: "mail.".to_owned(),
            ttl: 86400,
            r_class: DNSClass::IN,
            r_type: DNSType::NS,
            r_data: "mail.".to_owned(),
        }
    );

    let s = "@  86400  IN  NS    @";
    let rr: Result<ResourceRecord, ParseZoneDataErr> =
        ResourceRecord::new(s, Some(1000), None, Some("mail."), Some("google.com."));
    assert_eq!(
        rr.unwrap(),
        ResourceRecord {
            name: "mail.".to_owned(),
            ttl: 86400,
            r_class: DNSClass::IN,
            r_type: DNSType::NS,
            r_data: "mail.".to_owned(),
        }
    );

    let s = "@  86400  IN  NS    @";
    let rr: Result<ResourceRecord, ParseZoneDataErr> =
        ResourceRecord::new(s, Some(1000), None, Some("mail"), Some("google.com."));
    assert_eq!(
        rr.unwrap(),
        ResourceRecord {
            name: "mail.google.com.".to_owned(),
            ttl: 86400,
            r_class: DNSClass::IN,
            r_type: DNSType::NS,
            r_data: "mail.google.com.".to_owned(),
        }
    );
}

#[test]
fn test_parse_rr_from_str_err() {
    let s = "@  IN  NS  @";
    let rr: Result<ResourceRecord, ParseZoneDataErr> =
        ResourceRecord::new(s, Some(1000), None, None, None);
    assert_eq!(rr.unwrap_err(), ParseZoneDataErr::NoDefaultDomain);

    let rr: Result<ResourceRecord, ParseZoneDataErr> =
        ResourceRecord::new(s, Some(1000), None, Some("mail"), None);
    assert_eq!(rr.unwrap_err(), ParseZoneDataErr::NoOriginDomain);

    let rr: Result<ResourceRecord, ParseZoneDataErr> =
        ResourceRecord::new(s, None, None, Some("mail"), Some("google.com."));
    assert_eq!(rr.unwrap_err(), ParseZoneDataErr::NoDefaultTTL);

    let rr: Result<ResourceRecord, ParseZoneDataErr> =
        ResourceRecord::new(s, None, None, Some("-."), None);
    assert_eq!(
        rr.unwrap_err(),
        ParseZoneDataErr::ValidDomainErr("-.".to_owned())
    );

    let s = "mail. NS  ns1.google.com.";
    let rr: Result<ResourceRecord, ParseZoneDataErr> =
        ResourceRecord::new(s, None, None, None, None);
    assert_eq!(rr.unwrap_err(), ParseZoneDataErr::NoDefaultTTL);
}
