use crate::dnsname::DNSName;
use crate::meta::{DNSClass, DNSType, ResourceRecord};
use crate::qtype::decode_dns_data_from_string;
use crate::utils::{is_fqdn, valid_domain};
use otterlib::errors::ParseZoneDataErr;

impl ResourceRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn from_zone_data(
        rr_str: &str,
        default_ttl: Option<u32>,
        default_class: Option<DNSClass>,
        default_domain: Option<&str>,
        default_origin: Option<&str>,
    ) -> Result<Self, ParseZoneDataErr> {
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
                _ => return Err(ParseZoneDataErr::NoDomainTypeErr),
            }
        }

        if with_default_domain {
            if let Some(default_domain_str) = default_domain {
                name = default_domain_str;
            } else {
                return Err(ParseZoneDataErr::NoDefaultDomainErr);
            }
        }
        let domain_fqdn: String;
        if !is_fqdn(name) {
            if let Some(origin) = default_origin {
                domain_fqdn = format!("{}.{}", name.to_owned(), origin.to_owned());
            } else {
                return Err(ParseZoneDataErr::NoOriginDomainErr);
            }
        } else {
            domain_fqdn = name.to_owned();
        }
        if !valid_domain(name) {
            return Err(ParseZoneDataErr::ValidDomainErr(name.to_owned()));
        }
        // token must be ttl or class or type
        // after this code, at least we don't need care about ttl.
        if let Ok(t) = gen_ttl_from_token(token) {
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
                            return Err(ParseZoneDataErr::NoDomainTypeErr);
                        }
                    } else if token == "CH" || token == "ch" {
                        r_class = DNSClass::CH;
                        // get a new type
                        if let Some(token) = s_iter.next() {
                            // token is domain type now
                            rtype = token;
                        } else {
                            return Err(ParseZoneDataErr::NoDomainTypeErr);
                        }
                    } else {
                        // current token is type
                        rtype = token;
                    }
                } else {
                    return Err(ParseZoneDataErr::NoDomainTypeErr);
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
                return Err(ParseZoneDataErr::NoDomainTypeErr);
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
                            return Err(ParseZoneDataErr::NoOriginDomainErr);
                        }
                    } else {
                        rest_rdata_vec.push(default_domain_str.to_owned())
                    }
                } else {
                    return Err(ParseZoneDataErr::NoDefaultDomainErr);
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
                return Err(ParseZoneDataErr::NoDefaultTTLErr);
            }
        }
        let dname = DNSName::new(domain_fqdn.as_str())?;
        match decode_dns_data_from_string(r_data.as_str(), r_type) {
            Ok(data) => Ok(ResourceRecord {
                name: dname,
                qtype: r_type,
                qclass: r_class,
                ttl,
                data: Some(data),
            }),
            Err(err) => Err(err),
        }
    }
}

fn gen_ttl_from_token(token: &str) -> Result<u32, ParseZoneDataErr> {
    let mut ttl: u32 = 0;
    let mut temp: u32 = 0;
    for i in token.chars() {
        match i {
            's' | 'S' => ttl += temp,
            'm' | 'M' => ttl += temp * 60,
            'h' | 'H' => ttl += temp * 60 * 60,
            'd' | 'D' => ttl += temp * 60 * 60 * 24,
            'w' | 'W' => ttl += temp * 60 * 60 * 24 * 7,
            '0' | '1' | '2' | '3' | '4' | '5' | '6' | '7' | '8' | '9' => {
                temp *= 10;
                temp += u32::from(i) - 48;
                continue;
            }
            _ => return Err(ParseZoneDataErr::ParseDNSFromStrError(token.to_owned())),
        }
        temp = 0;
    }
    Ok(ttl + temp)
}

#[cfg(test)]
mod record {
    use crate::dnsname::DNSName;
    use crate::meta::{DNSClass, DNSType, ResourceRecord};
    use crate::qtype::{DnsTypeA, DnsTypeNS};
    use crate::record::gen_ttl_from_token;
    use otterlib::errors::ParseZoneDataErr;
    use std::convert::TryFrom;

    #[test]
    fn test_from_rr_into_answer() {
        let s = "mail.  86400   IN  A     192.0.2.3 ; this is a comment";
        let raw_rr = ResourceRecord::from_zone_data(s, None, None, None, None).unwrap();
        let resourc = ResourceRecord {
            name: DNSName::new("mail.").unwrap(),
            qtype: DNSType::A,
            qclass: DNSClass::IN,
            ttl: 86400,
            data: Some(Box::new(DnsTypeA::new("192.0.2.3").unwrap())),
        };
        match ResourceRecord::try_from(raw_rr) {
            Ok(rr) => {
                assert_eq!(resourc, rr);
                assert!(true);
            }
            Err(_) => {
                assert!(false);
            }
        }

        let s = "mail  86400   IN  A     192.0.2.3 ; this is a comment";
        let raw_rr =
            ResourceRecord::from_zone_data(s, None, None, None, Some("cnnic.cn.")).unwrap();
        let resourc = ResourceRecord {
            name: DNSName::new("mail.cnnic.cn.").unwrap(),
            qtype: DNSType::A,
            qclass: DNSClass::IN,
            ttl: 86400,
            data: Some(Box::new(DnsTypeA::new("192.0.2.3").unwrap())),
        };
        match ResourceRecord::try_from(raw_rr) {
            Ok(rr) => {
                assert_eq!(resourc, rr);
                assert!(true);
            }
            Err(_) => {
                assert!(false);
            }
        }

        let s = "mail.    86400   IN  A     192.0.2.3 ; this is a comment";
        let raw_rr =
            ResourceRecord::from_zone_data(s, Some(1000), None, None, Some("cnnic.cn.")).unwrap();
        let resourc = ResourceRecord {
            name: DNSName::new("mail.").unwrap(),
            qtype: DNSType::A,
            qclass: DNSClass::IN,
            ttl: 86400,
            data: Some(Box::new(DnsTypeA::new("192.0.2.3").unwrap())),
        };
        match ResourceRecord::try_from(raw_rr) {
            Ok(rr) => {
                assert_eq!(resourc, rr);
                assert!(true);
            }
            Err(_) => {
                assert!(false);
            }
        }

        let s = " 86400 IN  A     192.0.2.3";
        let rr: Result<ResourceRecord, ParseZoneDataErr> =
            ResourceRecord::from_zone_data(s, Some(1000), None, Some("mail."), None);
        assert_eq!(
            rr.unwrap(),
            ResourceRecord {
                name: DNSName::new("mail.").unwrap(),
                qtype: DNSType::A,
                qclass: DNSClass::IN,
                ttl: 86400,
                data: Some(Box::new(DnsTypeA::new("192.0.2.3").unwrap()))
            }
        );

        let s = " IN  A     192.0.2.3";
        let rr: Result<ResourceRecord, ParseZoneDataErr> =
            ResourceRecord::from_zone_data(s, Some(1000), None, Some("mail."), None);
        assert_eq!(
            rr.unwrap(),
            ResourceRecord {
                name: DNSName::new("mail.").unwrap(),
                qtype: DNSType::A,
                qclass: DNSClass::IN,
                ttl: 1000,
                data: Some(Box::new(DnsTypeA::new("192.0.2.3").unwrap()))
            }
        );
        // TODO:
        // let s = "  IN  SOA    localhost. root.localhost.  1999010100 ( 10800 900 604800 86400 ) ";
        // let rr: Result<ResourceRecord, ParseZoneDataErr> =
        //     ResourceRecord::from_zone_data(s, Some(1000), None, Some("mail"), Some("google.com."));
        // assert_eq!(
        //     rr.unwrap(),
        //     ResourceRecord {
        //         name: DNSName::new("mail.google.com.").unwrap(),
        //         qtype: DNSType::A,
        //         qclass: DNSClass::IN,
        //         ttl: 1000,
        //         data: Some(Box::new(DnsTypeSOA::new(
        //             "localhost.",
        //             "root.localhost.",
        //             1999010100, 10800, 900, 604800, 86400).unwrap())),
        //     }
        // );
        let s = "IN.  A     192.0.2.3";
        let rr: Result<ResourceRecord, ParseZoneDataErr> =
            ResourceRecord::from_zone_data(s, Some(1000), None, None, None);
        assert_eq!(
            rr.unwrap(),
            ResourceRecord {
                name: DNSName::new("IN.").unwrap(),
                qtype: DNSType::A,
                qclass: DNSClass::IN,
                ttl: 1000,
                data: Some(Box::new(DnsTypeA::new("192.0.2.3").unwrap()))
            }
        );

        let s = "@  86400  IN  NS    @";
        let rr: Result<ResourceRecord, ParseZoneDataErr> =
            ResourceRecord::from_zone_data(s, Some(1000), None, Some("mail"), Some("google.com."));
        assert_eq!(
            rr.unwrap(),
            ResourceRecord {
                name: DNSName::new("mail.google.com.").unwrap(),
                qtype: DNSType::NS,
                qclass: DNSClass::IN,
                ttl: 86400,
                data: Some(Box::new(DnsTypeNS::new("mail.google.com.").unwrap()))
            }
        );
    }
    #[test]
    fn test_gen_ttl_from_token() {
        let tcs = [
            ("10m", 600),
            ("11m", 660),
            ("1m", 60),
            ("1h", 3600),
            ("1001", 1001),
            ("1d", 86400),
            ("1w", 86400 * 7),
        ];
        for tc in tcs.iter() {
            assert_eq!(gen_ttl_from_token(tc.0).unwrap(), tc.1);
        }
    }
}
