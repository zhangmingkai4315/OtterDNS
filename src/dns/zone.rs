use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

use regex::Regex;
use crate::dns::domain::{valid_domain, is_fqdn};
use crate::dns::record::{RecordClass, ResourceRecord};
use crate::dns::errors::*;

pub trait ZoneReader{
    fn read_line(&self) -> &str;
}

struct ZoneStr<'a>{
    data: Option<&'a str>,
    empty_line_checker: Regex
}

impl<'a> ZoneStr<'a>{
    fn new(data: &'a str) -> ZoneStr{
        ZoneStr{
            data: Some(data),
            empty_line_checker: Regex::new(r"^\s*$").unwrap(),
        }
    }
}

impl<'a> Iterator for ZoneStr<'a>{
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
                    if let Some(line_cutter) = line.find(";") {
                        *line = &line[..line_cutter];
                    }
                    // Empty lines are allowed; any combination of tabs and spaces acts as a delimiter.
                    if line.is_empty() || self.empty_line_checker.is_match(line) {
                        break 'inner;
                    }
                    multi_line = multi_line + line.matches('(').count() - line.matches(')').count();
                    joined_line.push(line.clone());
                    if multi_line == 0 {
                        break 'outer;
                    } else {
                        break 'inner;
                    }
                }
            }
        }
        if multi_line != 0{
            return None
        }
        if joined_line.len() == 0 {
            return None
        }
        return Some(joined_line.join(""));
    }
}

struct Zone<T> where T: Iterator<Item = String>{
    line_iterator: T,
    // because the directive ,for example $ORIGIN, $TTL and $INCLUDE
    // we need hold those information for update
    default_origin: Option<String>,
    current_ttl: Option<u32>,
    current_class: Option<RecordClass>,
    current_origin: Option<String>,
    current_domain: Option<String>,


}

impl<T> Zone<T> where T: Iterator<Item = String>{
    fn new(&self, line_iterator: T, default_origin: Option<String>) -> Zone<T>{
        Zone{
            line_iterator,
            current_domain: None,
            current_class: None,
            current_origin: default_origin.clone(),
            current_ttl: None,
            default_origin: default_origin.clone(),
        }
    }

    fn update_ttl(&mut self, ttl: u32){
        self.current_ttl = Some(ttl);
    }

    fn update_class(&mut self, r_class: RecordClass){
        self.current_class = Some(r_class)
    }

    fn update_meta(&mut self, line: String)->Result<(), ParseZoneErr>{
        // line is start with $ then split it take second token.
        let mut spliter = line.split_whitespace();
        match spliter.next() {
            Some(v) if v.to_uppercase() == "$TTL".to_owned() => {
                if let Ok(token) = spliter.next().unwrap().parse::<u32>(){
                    self.update_ttl(token);
                } else{
                    return Err(ParseZoneErr::ParseZoneDataError(format!("ttl directive parse error: {}", line)))
                }
            },
            Some(v ) if v.to_uppercase() == "$ORIGIN".to_owned() => {
                let origin = spliter.next().unwrap();
                if is_fqdn(origin) && valid_domain(origin){
                    self.default_origin = Some(origin.to_owned());
                }else{
                    return Err(ParseZoneErr::from(ParseRRErr::ValidOriginErr(origin.to_owned())));
                }
            },
            Some(v ) if v.to_uppercase() == "$INCLUDE".to_owned() => {
                unimplemented!()
            }
            // started with $ but unknown
            Some(_) => { return Err(ParseZoneErr::ParseZoneDataError(format!("unknown directive: {}", line)))}
            _ => {return  Err(ParseZoneErr::ParseZoneDataError(format!("unknown directive: {}", line))) }
        }
        return Ok(());
    }
}

impl<T> Iterator for Zone<T> where T: Iterator<Item = String>{
    type Item = Result<ResourceRecord, ParseZoneErr>;

    fn next(&mut self) -> Option<Self::Item> {
        loop{
            if let Some(line)  = self.line_iterator.next(){
                if line.starts_with("$"){
                    if let Err(e) = self.update_meta(line){
                        return  Some(Err(ParseZoneErr::from(e)));
                    };
                }else{
                     match ResourceRecord::new((line as String).as_str(),
                                                    self.current_ttl,
                                                    self.current_class,
                                                    self.current_domain.as_deref(),
                                                    self.current_origin.as_deref()){
                         Ok(v) => return Some(Ok(v)),
                         Err(e) => return Some(Err(ParseZoneErr::from(e))),
                     }
                }
            }else{
                break;
            }
        }
        return None;
    }
}



struct ZoneFileParser {
    lines: io::Result<io::Lines<io::BufReader<File>>>,
    empty_line_checker: Regex,
}

impl ZoneFileParser {
    fn new(path: &str) -> Result<ZoneFileParser, ParseZoneErr>{
        // check file exist
        match std::fs::metadata(path) {
            Ok(_) => {
                return  Ok(ZoneFileParser {
                    lines: read_lines(path),
                    empty_line_checker: Regex::new(r"^\s*$").unwrap(),
                });
            },
            Err(err) => {
                return Err(ParseZoneErr::FileNotExist(err.to_string()));
            }
        }
    }
}

impl Iterator for ZoneFileParser {
    type Item = String;
    fn next(&mut self) -> Option<Self::Item> {
        let mut joined_line = vec![];
        let mut multi_line = 0;
        if self.lines.is_err(){
           return None;
        }
        let line_iter = self.lines.as_mut().unwrap();
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
                        }else{
                            new_line = _line;
                        }
                        // Empty lines are allowed; any combination of tabs and spaces acts as a delimiter.
                        if new_line.is_empty() || self.empty_line_checker.is_match(new_line.as_str()) {
                            break 'inner;
                        }
                        multi_line = multi_line + new_line.matches('(').count() - new_line.matches(')').count();
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
        if multi_line != 0{
            return None
        }
        if joined_line.len() == 0 {
            return None
        }
        Some(joined_line.join::<&str>(""))
    }
}




fn read_lines<P>(filename: P)->io::Result<io::Lines<io::BufReader<File>>>
where P: AsRef<Path>{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}


#[test]
fn test_zone_str_iterator(){
    let  zone_str = ZoneStr::new("ns            IN  A     192.0.2.2             ; IPv4 address for ns.example.com
              IN  AAAA  2001:db8:10::2        ; IPv6 address for ns.example.com");
    let mut iter = zone_str.into_iter();
    assert_eq!(iter.next(), Some("ns            IN  A     192.0.2.2             ".to_owned()));
    assert_eq!(iter.next(), Some("              IN  AAAA  2001:db8:10::2        ".to_owned()));
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

    let  zone_str = ZoneStr::new("


ns            IN  A     192.0.2.2             ; IPv4 address for ns.example.com
              IN  AAAA  2001:db8:10::2        ; IPv6 address for ns.example.com");
    let mut iter = zone_str.into_iter();
    assert_eq!(iter.next(), Some("ns            IN  A     192.0.2.2             ".to_owned()));
    assert_eq!(iter.next(), Some("              IN  AAAA  2001:db8:10::2        ".to_owned()));
    assert_eq!(iter.next(), None);

    let  zone_str = ZoneStr::new("


ns            IN  A     192.0.2.2             ; IPv4 address for ns.example.com

");
    let mut iter = zone_str.into_iter();
    assert_eq!(iter.next(), Some("ns            IN  A     192.0.2.2             ".to_owned()));
    assert_eq!(iter.next(), None);

    let  zone_str = ZoneStr::new(".			86391 IN SOA a.root-servers.net. nstld.verisign-grs.com. (
				2020091101 ; serial
				1800       ; refresh (30 minutes)
				900        ; retry (15 minutes)
				604800     ; expire (1 week)
				86400      ; minimum (1 day)
				)");
    let mut iter = zone_str.into_iter();
    assert_eq!(iter.next(), Some(".			86391 IN SOA a.root-servers.net. nstld.verisign-grs.com. (				2020091101 				1800       				900        				604800     				86400      				)".to_owned()));
    assert_eq!(iter.next(), None);


    let  zone_str = ZoneStr::new(".			180017	IN	NS	e.root-servers.net.
.			180017	IN	NS	d.root-servers.net.
.			180017	IN	NS	l.root-servers.net.");
    let mut iter = zone_str.into_iter();
    assert_eq!(iter.next(), Some(".			180017	IN	NS	e.root-servers.net.".to_owned()));
    assert_eq!(iter.next(), Some(".			180017	IN	NS	d.root-servers.net.".to_owned()));
    assert_eq!(iter.next(), Some(".			180017	IN	NS	l.root-servers.net.".to_owned()));
    assert_eq!(iter.next(), None);

    let  zone_str = ZoneStr::new("www.baidu.com.		176	IN	CNAME	www.a.shifen.com.
www.a.shifen.com.	300	IN	A	61.135.185.32
www.a.shifen.com.	300	IN	A	61.135.169.121

");
    let mut iter = zone_str.into_iter();
    assert_eq!(iter.next(), Some("www.baidu.com.		176	IN	CNAME	www.a.shifen.com.".to_owned()));
    assert_eq!(iter.next(), Some("www.a.shifen.com.	300	IN	A	61.135.185.32".to_owned()));
    assert_eq!(iter.next(), Some("www.a.shifen.com.	300	IN	A	61.135.169.121".to_owned()));
    assert_eq!(iter.next(), None);

    let  zone_str = ZoneStr::new("");
    let mut iter = zone_str.into_iter();
    assert_eq!(iter.next(), None);

    let  zone_str = ZoneStr::new("; comment");
    let mut iter = zone_str.into_iter();
    assert_eq!(iter.next(), None);

    let zone_str = ZoneStr::new("\r   \r\r\r and this a new line;with comment \r end!");
    let mut iter = zone_str.into_iter();
    assert_eq!(iter.next(), Some(" and this a new line".to_owned()));
    assert_eq!(iter.next(), Some(" end!".to_owned()));

    let zone_str = ZoneStr::new("\r;comment   \r\r\r ;comment\r ;comment");
    let mut iter = zone_str.into_iter();
    assert_eq!(iter.next(),None);
}




