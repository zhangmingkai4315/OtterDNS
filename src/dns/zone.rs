use super::record::ResourceRecord;
use std::path::Iter;
use regex::Regex;
use itertools::Itertools;

pub trait ZoneReader{
    fn Readline(&self) -> &str;
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
            'inner: loop {
                let mut new_line: Option<&str>;
                /// loop for a valid line
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
                    // remove comment from first ; to the end of line
                    if let Some(line_cutter) = line.find(";") {
                        *line = &line[..line_cutter];
                    }
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
        if joined_line.len() == 0 {
            return None
        }
        return Some(joined_line.join(""));
    }
}


#[test]
fn test_zone_str_iterator(){
    let  zone_str = ZoneStr::new("this is a test line \n and this a new line \n end!");
    let mut iter = zone_str.into_iter();
    assert_eq!(iter.next(), Some("this is a test line ".to_owned()));
    assert_eq!(iter.next(), Some(" and this a new line ".to_owned()));
    assert_eq!(iter.next(), Some(" end!".to_owned()));

    let  zone_str = ZoneStr::new("this is a test line \n\n\n\n and this a new line \n end!");
    let mut iter = zone_str.into_iter();
    assert_eq!(iter.next(), Some("this is a test line ".to_owned()));
    assert_eq!(iter.next(), Some(" and this a new line ".to_owned()));
    assert_eq!(iter.next(), Some(" end!".to_owned()));

    let  zone_str = ZoneStr::new("this is a test line \n   \n\n\n and this a new line \n end!");
    let mut iter = zone_str.into_iter();
    assert_eq!(iter.next(), Some("this is a test line ".to_owned()));
    assert_eq!(iter.next(), Some(" and this a new line ".to_owned()));
    assert_eq!(iter.next(), Some(" end!".to_owned()));

    let  zone_str = ZoneStr::new("\n   \n\n\n and this a new line \n end!");
    let mut iter = zone_str.into_iter();
    assert_eq!(iter.next(), Some(" and this a new line ".to_owned()));
    assert_eq!(iter.next(), Some(" end!".to_owned()));

    let  zone_str = ZoneStr::new("\r\n   \r\n\r\n\r\n and this a new line \r\n end!");
    let mut iter = zone_str.into_iter();
    assert_eq!(iter.next(), Some(" and this a new line ".to_owned()));
    assert_eq!(iter.next(), Some(" end!".to_owned()));

    let  zone_str = ZoneStr::new("\r   \r\r\r and this a new line \r end!");
    let mut iter = zone_str.into_iter();
    assert_eq!(iter.next(), Some(" and this a new line ".to_owned()));
    assert_eq!(iter.next(), Some(" end!".to_owned()));

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




pub enum ParseZoneFileErr{
    FileNotExist(String),
    ReadFileError(String),
    ParseZoneDataError
}

#[derive(Debug)]
pub struct Zone{
    filepath: String,
    name: String,
    data: Vec<ResourceRecord>,
}

impl Zone{
    pub fn new(filepath: &str, name:&str)->Zone{
        Zone{
            filepath: filepath.to_owned(),
            name: name.to_owned(),
            data: vec![],
        }
    }

    pub fn parse_zone_file(&mut self)->Result<(),ParseZoneFileErr>{
        Err(ParseZoneFileErr::ParseZoneDataError)
    }

}
