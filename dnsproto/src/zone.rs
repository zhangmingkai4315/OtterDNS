#![allow(dead_code)]
use crate::errors::*;
use crate::meta::{DNSClass, ResourceRecord};
use crate::utils::{is_fqdn, valid_domain};
use regex::Regex;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

pub trait ZoneReader {
    fn read_line(&self) -> &str;
}

struct ZoneStr<'a> {
    data: Option<&'a str>,
    empty_line_checker: Regex,
}

impl<'a> ZoneStr<'a> {
    fn new(data: &'a str) -> ZoneStr {
        ZoneStr {
            data: Some(data),
            empty_line_checker: Regex::new(r"^\s*$").unwrap(),
        }
    }
}

impl<'a> Iterator for ZoneStr<'a> {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        let mut joined_line = vec![];
        let mut multi_line = 0;
        'outer: loop {
            // loop for a truncated line (with '(' or ')' )
            'inner: loop {
                let mut new_line: Option<&str>;
                // loop for a valid line
                let remainder = self.data.as_mut()?;
                if let Some(next) = remainder.find(|c: char| c == '\n' || c == '\r') {
                    let mut sep_len = 1;
                    if remainder[next + 1..].starts_with('\r') {
                        sep_len = 2
                    }
                    let until_delimiter = &remainder[..next];
                    *remainder = &remainder[(next + sep_len)..];
                    new_line = Some(until_delimiter);
                } else {
                    // current is the last line
                    if let Some(token) = self.data.take() {
                        new_line = Some(token);
                    } else {
                        new_line = None;
                    }
                }
                if let Some(line) = new_line.as_mut() {
                    // Comments start with a semicolon ";" and go to the end of line.
                    if let Some(line_cutter) = line.find(';') {
                        *line = &line[..line_cutter];
                    }
                    // Empty lines are allowed; any combination of tabs and spaces acts as a delimiter.
                    if line.is_empty() || self.empty_line_checker.is_match(line) {
                        break 'inner;
                    }
                    multi_line = multi_line + line.matches('(').count() - line.matches(')').count();
                    joined_line.push(<&str>::clone(line));
                    if multi_line == 0 {
                        break 'outer;
                    } else {
                        break 'inner;
                    }
                }
            }
        }
        if multi_line != 0 {
            return None;
        }
        if joined_line.is_empty() {
            return None;
        }
        Some(joined_line.join(""))
    }
}

struct Zone<T>
where
    T: Iterator<Item = String>,
{
    line_iterator: T,
    // because the directive ,for example $ORIGIN, $TTL and $INCLUDE
    // we need hold those information for update
    default_origin: Option<String>,
    current_ttl: Option<u32>,
    current_class: Option<DNSClass>,
    current_origin: Option<String>,
    current_domain: Option<String>,
}

impl<T> Zone<T>
where
    T: Iterator<Item = String>,
{
    fn new(line_iterator: T, default_origin: Option<String>) -> Zone<T> {
        if let Some(ref origin) = default_origin {
            // must be fqdn
            if !is_fqdn(origin.as_str()) {
                panic!("origin must be fqdn")
            }
        }
        Zone {
            line_iterator,
            current_domain: None,
            current_class: None,
            current_origin: default_origin.clone(),
            current_ttl: None,
            default_origin,
        }
    }

    fn update_ttl(&mut self, ttl: u32) {
        self.current_ttl = Some(ttl);
    }

    fn update_class(&mut self, qclass: DNSClass) {
        self.current_class = Some(qclass)
    }

    fn update_meta(&mut self, line: String) -> Result<(), DNSProtoErr> {
        // line is start with $ then split it take second token.
        let mut spliter = line.split_whitespace();
        match spliter.next() {
            Some(token) if token.to_uppercase().eq("$TTL") => {
                if let Ok(token) = spliter.next().unwrap().parse::<u32>() {
                    self.update_ttl(token);
                } else {
                    return Err(DNSProtoErr::ParseZoneDataErr(
                        ParseZoneDataErr::ValidTTLErr(line),
                    ));
                }
            }
            Some(token) if token.to_uppercase().eq("$ORIGIN") => {
                let origin = spliter.next().unwrap();
                if is_fqdn(origin) && valid_domain(origin) {
                    self.default_origin = Some(origin.to_owned());
                } else {
                    return Err(DNSProtoErr::ParseZoneDataErr(
                        ParseZoneDataErr::ValidTTLErr(origin.to_owned()),
                    ));
                }
            }
            Some(val) if val.to_uppercase().eq("$INCLUDE") => unimplemented!(),
            // started with $ but unknown
            _ => {
                return Err(DNSProtoErr::ParseZoneDataErr(ParseZoneDataErr::GeneralErr(
                    format!("unknown directive: {}", line),
                )));
            }
        }
        Ok(())
    }
}

impl<T> Iterator for Zone<T>
where
    T: Iterator<Item = String>,
{
    type Item = Result<ResourceRecord, DNSProtoErr>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(line) = self.line_iterator.next() {
            if line.starts_with('$') {
                if let Err(e) = self.update_meta(line) {
                    return Some(Err(e));
                };
            } else {
                return match ResourceRecord::from_zone_data(
                    (line as String).as_str(),
                    self.current_ttl,
                    self.current_class,
                    self.current_domain.as_deref(),
                    self.current_origin.as_deref(),
                ) {
                    Ok(rr) => {
                        self.current_domain = Some(rr.name.to_string());
                        self.current_class = Some(rr.qclass);
                        self.current_ttl = Some(rr.ttl);
                        Some(Ok(rr))
                    }
                    Err(err) => Some(Err(DNSProtoErr::ParseZoneDataErr(err))),
                };
            }
        }
        None
    }
}

struct ZoneFileParser {
    lines: io::Result<io::Lines<io::BufReader<File>>>,
    empty_line_checker: Regex,
}

impl ZoneFileParser {
    fn new(path: &str) -> Result<ZoneFileParser, DNSProtoErr> {
        // check file exist
        match std::fs::metadata(path) {
            Ok(_) => Ok(ZoneFileParser {
                lines: read_lines(path),
                empty_line_checker: Regex::new(r"^\s*$").unwrap(),
            }),
            Err(err) => Err(DNSProtoErr::IOError {
                path: path.to_string(),
                err: err.to_string(),
            }),
        }
    }
}

impl Iterator for ZoneFileParser {
    type Item = String;
    fn next(&mut self) -> Option<Self::Item> {
        let mut joined_line = vec![];
        let mut multi_line = 0;
        if self.lines.is_err() {
            return None;
        }
        let line_iter = self.lines.as_mut().unwrap();
        #[allow(clippy::never_loop)]
        'outer: loop {
            // loop for a truncated line (with '(' or ')' )
            'inner: loop {
                // loop for a valid line
                let new_line;
                match line_iter.next() {
                    Some(Ok(_line)) => {
                        // Comments start with a semicolon ";" and go to the end of line.
                        if let Some(line_cutter) = _line.find(|x| x == ';') {
                            new_line = _line.split_at(line_cutter).0.to_owned();
                        } else {
                            new_line = _line;
                        }
                        // Empty lines are allowed; any combination of tabs and spaces acts as a delimiter.
                        if new_line.is_empty()
                            || self.empty_line_checker.is_match(new_line.as_str())
                        {
                            break 'inner;
                        }
                        multi_line = multi_line + new_line.matches('(').count()
                            - new_line.matches(')').count();
                        joined_line.push(new_line.clone());
                        if multi_line == 0 {
                            break 'outer;
                        } else {
                            break 'inner;
                        }
                    }
                    _ => break 'outer,
                }
            }
        }
        if multi_line != 0 {
            return None;
        }
        if joined_line.is_empty() {
            return None;
        }
        Some(joined_line.join::<&str>(""))
    }
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

#[test]
fn test_zone_str_iterator() {
    let zone_str = ZoneStr::new(
        "ns            IN  A     192.0.2.2             ; IPv4 address for ns.example.com
              IN  AAAA  2001:db8:10::2        ; IPv6 address for ns.example.com",
    );
    let mut iter = zone_str.into_iter();
    assert_eq!(
        iter.next(),
        Some("ns            IN  A     192.0.2.2             ".to_owned())
    );
    assert_eq!(
        iter.next(),
        Some("              IN  AAAA  2001:db8:10::2        ".to_owned())
    );
    assert_eq!(iter.next(), None);

    let  zone_str = ZoneStr::new("$ORIGIN example.com.     ; designates the start of this zone file in the namespace
$TTL 3600                ; default expiration time (in seconds) of all RRs without their own TTL value");
    let mut iter = zone_str.into_iter();
    assert_eq!(iter.next(), Some("$ORIGIN example.com.     ".to_owned()));
    assert_eq!(iter.next(), Some("$TTL 3600                ".to_owned()));
    assert_eq!(iter.next(), None);

    let  zone_str = ZoneStr::new("$ORIGIN example.com.     ; designates the start of this zone file in the namespace


$TTL 3600                ; default expiration time (in seconds) of all RRs without their own TTL value");
    let mut iter = zone_str.into_iter();
    assert_eq!(iter.next(), Some("$ORIGIN example.com.     ".to_owned()));
    assert_eq!(iter.next(), Some("$TTL 3600                ".to_owned()));
    assert_eq!(iter.next(), None);

    let zone_str = ZoneStr::new(
        "


ns            IN  A     192.0.2.2             ; IPv4 address for ns.example.com
              IN  AAAA  2001:db8:10::2        ; IPv6 address for ns.example.com",
    );
    let mut iter = zone_str.into_iter();
    assert_eq!(
        iter.next(),
        Some("ns            IN  A     192.0.2.2             ".to_owned())
    );
    assert_eq!(
        iter.next(),
        Some("              IN  AAAA  2001:db8:10::2        ".to_owned())
    );
    assert_eq!(iter.next(), None);

    let zone_str = ZoneStr::new(
        "


ns            IN  A     192.0.2.2             ; IPv4 address for ns.example.com

",
    );
    let mut iter = zone_str.into_iter();
    assert_eq!(
        iter.next(),
        Some("ns            IN  A     192.0.2.2             ".to_owned())
    );
    assert_eq!(iter.next(), None);

    let zone_str = ZoneStr::new(
        ".			86391 IN SOA a.root-servers.net. nstld.verisign-grs.com. (
				2020091101 ; serial
				1800       ; refresh (30 minutes)
				900        ; retry (15 minutes)
				604800     ; expire (1 week)
				86400      ; minimum (1 day)
				)",
    );
    let mut iter = zone_str.into_iter();
    assert_eq!(iter.next(), Some(".	86391 IN SOA a.root-servers.net. nstld.verisign-grs.com. ( 2020091101 1800 900 604800 86400 )".to_owned()));
    assert_eq!(iter.next(), None);

    let zone_str = ZoneStr::new(
        ".			180017	IN	NS	e.root-servers.net.
.			180017	IN	NS	d.root-servers.net.
.			180017	IN	NS	l.root-servers.net.",
    );
    let mut iter = zone_str.into_iter();
    assert_eq!(
        iter.next(),
        Some(".			180017	IN	NS	e.root-servers.net.".to_owned())
    );
    assert_eq!(
        iter.next(),
        Some(".			180017	IN	NS	d.root-servers.net.".to_owned())
    );
    assert_eq!(
        iter.next(),
        Some(".			180017	IN	NS	l.root-servers.net.".to_owned())
    );
    assert_eq!(iter.next(), None);

    let zone_str = ZoneStr::new(
        "www.baidu.com.		176	IN	CNAME	www.a.shifen.com.
www.a.shifen.com.	300	IN	A	61.135.185.32
www.a.shifen.com.	300	IN	A	61.135.169.121

",
    );
    let mut iter = zone_str.into_iter();
    assert_eq!(
        iter.next(),
        Some("www.baidu.com.		176	IN	CNAME	www.a.shifen.com.".to_owned())
    );
    assert_eq!(
        iter.next(),
        Some("www.a.shifen.com.	300	IN	A	61.135.185.32".to_owned())
    );
    assert_eq!(
        iter.next(),
        Some("www.a.shifen.com.	300	IN	A	61.135.169.121".to_owned())
    );
    assert_eq!(iter.next(), None);

    let zone_str = ZoneStr::new("");
    let mut iter = zone_str.into_iter();
    assert_eq!(iter.next(), None);

    let zone_str = ZoneStr::new("; comment");
    let mut iter = zone_str.into_iter();
    assert_eq!(iter.next(), None);

    let zone_str = ZoneStr::new("\r   \r\r\r and this a new line;with comment \r end!");
    let mut iter = zone_str.into_iter();
    assert_eq!(iter.next(), Some(" and this a new line".to_owned()));
    assert_eq!(iter.next(), Some(" end!".to_owned()));

    let zone_str = ZoneStr::new("\r;comment   \r\r\r ;comment\r ;comment");
    let mut iter = zone_str.into_iter();
    assert_eq!(iter.next(), None);
}

#[test]
fn test_zone_iterator() {
    let zone_str = ZoneStr::new(
        "ns      86400      IN  A     192.0.2.2             ; IPv4 address for ns.example.com
              IN  AAAA  2001:db8:10::2        ; IPv6 address for ns.example.com",
    );
    let mut zone = Zone::new(zone_str, Some("google.com.".to_owned()));
    match zone.next() {
        Some(Ok(v)) => {
            assert_eq!(v.name, DNSName::new("ns.google.com.").unwrap());
            assert_eq!(v.qclass, DNSClass::IN);
            assert_eq!(v.qtype, DNSType::A);
            assert_eq!(
                (v.data.unwrap().as_ref()).to_string(),
                "192.0.2.2".to_owned()
            );
        }
        Some(Err(_e)) => {
            assert!(false);
        }
        None => {
            assert!(false);
        }
    }

    let zone_str = ZoneStr::new(
        "ns          IN  A     192.0.2.2             ; IPv4 address for ns.example.com
              IN  AAAA  2001:db8:10::2        ; IPv6 address for ns.example.com",
    );
    let mut zone = Zone::new(zone_str, Some("google.com.".to_owned()));
    match zone.next() {
        Some(Err(DNSProtoErr::ParseZoneDataErr(_))) => assert!(true),
        _ => {
            assert!(false);
        }
    }

    let zone_str = ZoneStr::new(
        "ns.    86400      IN  A     192.0.2.2             ; IPv4 address for ns.example.com
              IN  AAAA  2001:db8:10::2        ; IPv6 address for ns.example.com",
    );
    let mut zone = Zone::new(zone_str, None);
    match zone.next() {
        Some(Ok(v)) => {
            assert_eq!(v.name, DNSName::new("ns.").unwrap());
            assert_eq!(v.qclass, DNSClass::IN);
            assert_eq!(v.qtype, DNSType::A);
            assert_eq!(
                (v.data.unwrap().as_ref()).to_string(),
                "192.0.2.2".to_owned()
            );
        }
        _ => {
            assert!(false);
        }
    }

    let zone_str = ZoneStr::new(
        "\
; otter.fun DNS zonefile
$TTL 14400
otter.fun. 86400 IN  SOA  ns1.domain.com.  user.mail.com. (
				2020081601 ;Serial Number
				3600 ;refresh
				7200 ;retry
				1209600 ;expire
				86400 ;minimum
        )
otter.fun.   86400   IN	NS	ns1.domain.com.
otter.fun.   86400   IN	NS	ns2.domain.com.
otter.fun.   14400   IN	A	1.1.1.1
otter.fun.   14400   IN	MX	0     g33k.fun.
mail	    14400   IN	CNAME   otter.fun.
www	    14400   IN	CNAME   otter.fun.
ftp	    14400   IN	A       1.1.1.2
otter.fun.   14400   IN  TXT	\"v=spf1 +a +mx +ip4:1.1.1.1 ~all\"
default._domainkey  14400  IN   TXT   \"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ;\"
otter.fun.   14400   IN	TXT	google-site-verification=zxIkMo9ruPbMyGMy4KWbc0QkOoN9aF2iFPvDHc0o8Pg",
    );
    let mut zone = Zone::new(zone_str, Some("otter.fun.".to_owned()));
    if let Some(Ok(v)) = zone.next() {
        assert_eq!(v.name, DNSName::new("otter.fun.").unwrap());
        assert_eq!(v.qtype, DNSType::SOA);
        assert_eq!(v.qclass, DNSClass::IN);
        assert_eq!(v.ttl, 86400);
        assert_eq!(
            (v.data.unwrap().as_ref()).to_string(),
            "ns1.domain.com. user.mail.com. ( 2020081601 3600 7200 1209600 86400 )"
        );
    }
    if let Some(Ok(v)) = zone.next() {
        assert_eq!(v.name, DNSName::new("otter.fun.").unwrap());
        assert_eq!(v.qtype, DNSType::NS);
        assert_eq!(v.qclass, DNSClass::IN);
        assert_eq!(v.ttl, 86400);
        assert_eq!((v.data.unwrap().as_ref()).to_string(), "ns1.domain.com.");
    }
    if let Some(Ok(v)) = zone.next() {
        assert_eq!(v.name, DNSName::new("otter.fun.").unwrap());
        assert_eq!(v.qtype, DNSType::NS);
        assert_eq!(v.qclass, DNSClass::IN);
        assert_eq!(v.ttl, 86400);
        assert_eq!((v.data.unwrap().as_ref()).to_string(), "ns2.domain.com.");
    }
    if let Some(Ok(v)) = zone.next() {
        assert_eq!(v.name, DNSName::new("otter.fun.").unwrap());
        assert_eq!(v.qtype, DNSType::A);
        assert_eq!(v.ttl, 14400);
        assert_eq!(v.qclass, DNSClass::IN);
        assert_eq!((v.data.unwrap().as_ref()).to_string(), "1.1.1.1");
    }
    if let Some(Ok(v)) = zone.next() {
        assert_eq!(v.name, DNSName::new("otter.fun.").unwrap());
        assert_eq!(v.qtype, DNSType::MX);
        assert_eq!(v.qclass, DNSClass::IN);
        assert_eq!(v.ttl, 14400);
        // TODO: impl
        // assert_eq!((v.data.unwrap().as_ref()).to_string(),"0 g33k.fun.");
    }
    assert_eq!(zone.current_class, Some(DNSClass::IN));
    assert_eq!(zone.current_ttl, Some(14400));
    assert_eq!(zone.current_origin, Some("otter.fun.".to_owned()));
    if let Some(Ok(v)) = zone.next() {
        assert_eq!(v.name, DNSName::new("mail.otter.fun.").unwrap());
        assert_eq!(v.qtype, DNSType::CNAME);
        assert_eq!(v.ttl, 14400);
        assert_eq!(v.qclass, DNSClass::IN);
        // TODO: impl
        // assert_eq!((v.data.unwrap().as_ref()).to_string(),"0 g33k.fun.");
    }
    if let Some(Ok(v)) = zone.next() {
        assert_eq!(v.name, DNSName::new("www.otter.fun.").unwrap());
        assert_eq!(v.qtype, DNSType::CNAME);
        assert_eq!(v.ttl, 14400);
        assert_eq!(v.qclass, DNSClass::IN);
        // TODO: impl
        // assert_eq!((v.data.unwrap().as_ref()).to_string(),"0 g33k.fun.");
    }
    if let Some(Ok(v)) = zone.next() {
        assert_eq!(v.name, DNSName::new("ftp.otter.fun.").unwrap());
        assert_eq!(v.qtype, DNSType::A);
        assert_eq!(v.ttl, 14400);
        assert_eq!(v.qclass, DNSClass::IN);
        assert_eq!((v.data.unwrap().as_ref()).to_string(), "1.1.1.2");
    }

    if let Some(Ok(v)) = zone.next() {
        assert_eq!(v.name, DNSName::new("otter.fun.").unwrap());
        assert_eq!(v.qtype, DNSType::TXT);
        assert_eq!(v.qclass, DNSClass::IN);
        assert_eq!(v.ttl, 14400);
        // assert_eq!((v.data.unwrap().as_ref()).to_string(), "\"v=spf1 +a +mx +ip4:1.1.1.1 ~all\"");
    }
    if let Some(Ok(v)) = zone.next() {
        assert_eq!(
            v.name,
            DNSName::new("default._domainkey.otter.fun.").unwrap()
        );
        assert_eq!(v.qtype, DNSType::TXT);
        assert_eq!(v.qclass, DNSClass::IN);
        assert_eq!(v.ttl, 14400);
        // assert_eq!(
        //     v.data,
        //     "\"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ;\""
        // );
    }
    if let Some(Ok(v)) = zone.next() {
        assert_eq!(v.name, DNSName::new("otter.fun.").unwrap());
        assert_eq!(v.qtype, DNSType::TXT);
        assert_eq!(v.qclass, DNSClass::IN);
        assert_eq!(v.ttl, 14400);
        // assert_eq!(
        //     v.data,
        //     "google-site-verification=zxIkMo9ruPbMyGMy4KWbc0QkOoN9aF2iFPvDHc0o8Pg"
        // );
    }
}
