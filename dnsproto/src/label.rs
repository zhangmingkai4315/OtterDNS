use crate::errors::ParseZoneDataErr;
use crate::utils::*;
use std::prelude::v1::Vec;
use std::rc::Rc;
use std::str::FromStr;

pub type DNSTypeResult<T> = std::result::Result<T, String>;

#[derive(Debug, Clone, PartialOrd, PartialEq)]
pub struct Label(Rc<[u8]>);
impl Label {
    pub fn from_bytes(bytes: &[u8]) -> DNSTypeResult<Self> {
        if bytes.len() > 63 {
            return Err(format!("exceeds max length {} >63 ", bytes.len()));
        }
        Ok(Label(Rc::from(bytes)))
    }
}

impl FromStr for Label {
    type Err = String;
    fn from_str(label_str: &str) -> DNSTypeResult<Self> {
        if valid_label(label_str) {
            Ok(Label(Rc::from(label_str.as_bytes())))
        } else {
            Err(label_str.to_string())
        }
    }
}

// DomainName
#[derive(Debug, PartialOrd, PartialEq)]
pub struct DomainName {
    is_fqdn: bool,
    inner: Vec<Label>,
}

impl DomainName {
    fn new(domain: &str) -> Result<DomainName, ParseZoneDataErr> {
        if domain.is_empty() {
            return Ok(DomainName {
                is_fqdn: false,
                inner: vec![],
            });
        }
        if domain.eq(".") {
            return Ok(DomainName {
                is_fqdn: true,
                inner: vec![],
            });
        }
        let mut inner_vec = vec![];
        for i in domain.split('.') {
            if i.is_empty() {
                continue;
            }
            match Label::from_str(i) {
                Ok(val) => inner_vec.push(val),
                Err(_) => {
                    return Err(ParseZoneDataErr::ValidDomainErr(domain.to_owned()));
                }
            }
        }
        Ok(DomainName {
            inner: inner_vec,
            is_fqdn: is_fqdn(domain),
        })
    }
}

impl Default for DomainName {
    fn default() -> Self {
        DomainName {
            is_fqdn: false,
            inner: vec![],
        }
    }
}

impl FromStr for DomainName {
    type Err = ParseZoneDataErr;
    fn from_str(domain: &str) -> Result<Self, Self::Err> {
        DomainName::new(domain)
    }
}

#[test]
fn test_domain_name() {
    assert_eq!(
        "hello.google.com".parse::<DomainName>().unwrap(),
        DomainName {
            is_fqdn: false,
            inner: vec![
                Label::from_str("hello").unwrap(),
                Label::from_str("google").unwrap(),
                Label::from_str("com").unwrap()
            ]
        }
    );
    assert_eq!(
        "*.google.com".parse::<DomainName>().unwrap(),
        DomainName {
            is_fqdn: false,
            inner: vec![
                Label::from_str("*").unwrap(),
                Label::from_str("google").unwrap(),
                Label::from_str("com").unwrap()
            ]
        }
    );
    assert_eq!(
        "_srv.google.com".parse::<DomainName>().unwrap(),
        DomainName {
            is_fqdn: false,
            inner: vec![
                Label::from_str("_srv").unwrap(),
                Label::from_str("google").unwrap(),
                Label::from_str("com").unwrap()
            ]
        }
    );
    assert_eq!(
        "google.xn--abc.".parse::<DomainName>().unwrap(),
        DomainName {
            is_fqdn: true,
            inner: vec![
                Label::from_str("google").unwrap(),
                Label::from_str("xn--abc").unwrap()
            ]
        }
    );

    assert_eq!(
        "+hello.google.com".parse::<DomainName>().unwrap_err(),
        ParseZoneDataErr::ValidDomainErr("+hello.google.com".to_owned())
    );
    assert_eq!(
        "hello.&google.com".parse::<DomainName>().unwrap_err(),
        ParseZoneDataErr::ValidDomainErr("hello.&google.com".to_owned())
    );
    assert_eq!("".parse::<DomainName>().unwrap(), DomainName::default());
}
