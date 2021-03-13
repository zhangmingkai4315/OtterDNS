use crate::errors::ParseRRErr;
use crate::errors::ParseRRErr::ParseTypeErr;
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
    pub fn from_str(s: &str) -> DNSTypeResult<Self> {
        if valid_label(s) {
            Ok(Label(Rc::from(s.as_bytes())))
        } else {
            Err(format!("{}", s))
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
    fn to_string(&self) -> String {
        "".to_owned()
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
    type Err = ParseRRErr;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() == 0 || s == "." {
            // root domain as default
            return Ok(DomainName::default());
        }
        let mut domain = DomainName::default();
        domain.is_fqdn = is_fqdn(s);
        for i in s.split('.') {
            if i.len() == 0 {
                continue;
            }
            match Label::from_str(i) {
                Ok(v) => domain.inner.push(v),
                Err(e) => return Err(ParseTypeErr(format!("domain label validate fail: {}", e))),
            }
        }
        Ok(domain)
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
        ParseTypeErr("domain label validate fail: +hello".to_owned())
    );
    assert_eq!(
        "hello.&google.com".parse::<DomainName>().unwrap_err(),
        ParseTypeErr("domain label validate fail: &google".to_owned())
    );
    assert_eq!("".parse::<DomainName>().unwrap(), DomainName::default());
}
