// http://www.networksorcery.com/enp/protocol/dns.htm
use crate::utils::{is_fqdn, valid_label};
use nom::{Err::Incomplete, IResult, Needed};

// use crate::types::{DNSFrameEncoder, get_dns_struct_from_raw};
use crate::errors::ParseZoneDataErr;
use nom::lib::std::collections::HashMap;
use nom::lib::std::fmt::Formatter;

#[derive(Debug, PartialEq)]
pub struct DNSName {
    pub is_fqdn: bool,
    pub labels: Vec<String>,
}

impl Clone for DNSName {
    fn clone(&self) -> Self {
        DNSName {
            is_fqdn: self.is_fqdn,
            labels: self
                .labels
                .iter()
                .map(|f| f.to_string())
                .collect::<Vec<String>>(),
        }
    }
}

impl DNSName {
    #[allow(dead_code)]
    fn root() -> Self {
        DNSName {
            is_fqdn: true,
            labels: Vec::new(),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.labels.is_empty()
    }
    pub fn pop_back(&mut self) -> Option<String> {
        self.labels.pop()
    }
    pub fn push_back(&mut self, label: &str) {
        self.labels.push(label.into())
    }
    pub fn push_front(&mut self, label: &str) {
        self.labels.insert(0, label.into())
    }
    pub fn pop_front(&mut self) -> Option<String> {
        if self.labels.is_empty() {
            return None;
        }
        Some(self.labels.remove(0))
    }
    pub fn size(&self) -> usize {
        self.labels.len()
    }
    pub fn is_part_of(&self, dname: &DNSName) -> bool {
        if self.size() < dname.size() {
            return false;
        }
        for (current_label, dname_label) in self.labels.iter().rev().zip(dname.labels.iter().rev())
        {
            if current_label.eq(dname_label) {
                continue;
            } else {
                return false;
            }
        }
        return true;
    }

    pub fn new(domain: &str) -> Result<DNSName, ParseZoneDataErr> {
        if domain.is_empty() {
            return Ok(DNSName {
                is_fqdn: false,
                labels: vec![],
            });
        }
        if domain.eq(".") {
            return Ok(DNSName {
                is_fqdn: true,
                labels: vec![],
            });
        }
        let mut inner_vec = vec![];
        for i in domain.split('.') {
            if i.is_empty() {
                continue;
            }
            if !valid_label(i) {
                return Err(ParseZoneDataErr::ValidDomainErr(domain.to_owned()));
            } else {
                inner_vec.push(i.to_owned());
            }
        }
        Ok(DNSName {
            labels: inner_vec,
            is_fqdn: is_fqdn(domain),
        })
    }
    pub fn to_binary(&self, compression: Option<(&mut HashMap<String, usize>, usize)>) -> Vec<u8> {
        let mut binary_store: Vec<u8> = vec![];
        let mut index = 0;
        let mut with_pointer = false;
        let mut current_offset = 0;
        match compression {
            Some((store, offset)) => {
                for label in self.labels.iter() {
                    let current_key: String = (&self.labels[index..]).join(".");
                    index += 1;
                    match store.get(current_key.as_str()) {
                        Some(location) => {
                            let pointer = (*location) | 0xc000;
                            binary_store.push((pointer >> 8) as u8);
                            binary_store.push((pointer & 0x00ff) as u8);
                            with_pointer = true;
                            break;
                        }
                        _ => {
                            binary_store.push(label.len() as u8);
                            binary_store.extend_from_slice(label.as_bytes());
                            store.insert(current_key, offset + current_offset);
                            current_offset = current_offset + label.len() + 1;
                        }
                    }
                }
                if !with_pointer {
                    binary_store.push(0x00);
                }
            }
            _ => {
                for label in self.labels.iter() {
                    binary_store.push(label.len() as u8);
                    binary_store.extend_from_slice(label.as_bytes())
                }
                binary_store.push(0x00);
            }
        }
        binary_store
    }
}

impl std::fmt::Display for DNSName {
    fn fmt(&self, format: &mut Formatter<'_>) -> std::fmt::Result {
        let mut name = String::new();
        for label in &self.labels {
            name.push_str(label);
            name.push('.');
        }
        write!(format, "{}", name)
    }
}

impl Default for DNSName {
    fn default() -> Self {
        DNSName {
            is_fqdn: false,
            labels: Vec::new(),
        }
    }
}

pub fn parse_name<'a>(input: &'a [u8], original: &'_ [u8]) -> IResult<&'a [u8], DNSName> {
    let original_len = original.len();
    let mut shift: usize = 0;
    let mut labels = vec![];
    let input_len = input.len();
    loop {
        if shift >= 256 {
            break;
        }
        if shift + 1 > input_len {
            return Err(Incomplete(Needed::Unknown));
        }
        let size_or_pointer = input[shift] as usize;
        if size_or_pointer == 0 {
            shift += 1;
            break;
        }
        // only 00(normal name) / 11(pointer) and 01(edns?) is used right now
        match size_or_pointer >> 6 & 0xff {
            0 => {
                if (size_or_pointer + shift + 1) >= 256 {
                    return Err(Incomplete(Needed::Unknown));
                }
                if shift + 2 > input_len || shift + 2 + size_or_pointer > input_len {
                    return Err(Incomplete(Needed::Unknown));
                }
                let label = &input[shift + 1..shift + 1 + size_or_pointer];
                match std::str::from_utf8(&label) {
                    Ok(label) => labels.push(String::from(label)),
                    _ => return Err(Incomplete(Needed::Unknown)),
                }
                shift = shift + size_or_pointer + 1;
            }
            3 => {
                let pointer =
                    ((((input[shift] as u16) << 8) | input[shift + 1] as u16) & 0x0fff) as usize;
                let mut stop = pointer;
                loop {
                    if original[stop] == 0 {
                        break;
                    }
                    if stop >= original_len {
                        return Err(Incomplete(Needed::Unknown));
                    }
                    stop += 1;
                }
                let new_input = &original[pointer..=stop];
                match parse_name(new_input, original) {
                    Ok(ref mut dname) => labels.append(&mut dname.1.labels),
                    Err(_) => return Err(Incomplete(Needed::Unknown)),
                };
                shift += 2;
                return Ok((
                    &input[shift..],
                    DNSName {
                        is_fqdn: true,
                        labels,
                    },
                ));
            }
            _ => return Err(Incomplete(Needed::Unknown)),
        }
    }
    Ok((
        &input[shift..],
        DNSName {
            is_fqdn: true,
            labels,
        },
    ))
}

#[test]
fn test_dns_name_method() {
    let mut dname = DNSName::new("www.google.com.").unwrap();
    let other = DNSName::new("google.com.").unwrap();
    assert_eq!(dname.size(), 3);
    assert_eq!(other.size(), 2);
    assert_eq!(dname.is_part_of(&other), true);
    dname.push_front("test");
    assert_eq!(dname.size(), 4);
    assert_eq!(dname.is_part_of(&other), true);
    dname.push_back("app");
    assert_eq!(dname.size(), 5);
    assert_eq!(dname.is_part_of(&other), false);

    assert_eq!(dname.pop_back(), Some(String::from("app")));
    assert_eq!(dname.size(), 4);
    assert_eq!(dname.is_part_of(&other), true);

    assert_eq!(dname.pop_front(), Some(String::from("test")));
    assert_eq!(dname.size(), 3);
    assert_eq!(dname.is_part_of(&other), true);

    assert_eq!(dname.is_empty(), false);
    let dname = DNSName::new(".").unwrap();
    assert_eq!(dname.is_empty(), true);
}

#[test]
fn test_dns_name_parse() {
    let raw = [
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
    ];
    let dname = parse_name(&raw[..], &[]);
    assert_eq!(dname.is_ok(), true);
    let dname = dname.unwrap();
    assert_eq!(dname.1.labels.len(), 2);
    assert_eq!(dname.1.to_string(), String::from("google.com."));

    let raw = [
        0x10, 0x63, 0x74, 0x2d, 0x62, 0x6a, 0x73, 0x2d, 0x73, 0x67, 0x68, 0x2d, 0x30, 0x30, 0x30,
        0x30, 0x31, 0x0d, 0x6f, 0x6f, 0x73, 0x2d, 0x63, 0x6e, 0x2d, 0x31, 0x38, 0x30, 0x36, 0x32,
        0x32, 0x08, 0x63, 0x74, 0x79, 0x75, 0x6e, 0x61, 0x70, 0x69, 0x02, 0x63, 0x6e, 0x00,
    ];
    let dname = parse_name(&raw, &[]);
    assert_eq!(dname.is_ok(), true);
    let dname = dname.unwrap();

    assert_eq!(dname.1.labels.len(), 4);
    assert_eq!(
        dname.1.to_string(),
        String::from("ct-bjs-sgh-00001.oos-cn-180622.ctyunapi.cn.")
    );

    let raw = [];
    let dname = parse_name(&raw, &[]);
    assert_eq!(dname.is_ok(), false);

    let raw = [0x01];
    let dname = parse_name(&raw, &[]);
    assert_eq!(dname.is_ok(), false);

    let raw = [
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x40, 0x00, 0x04, 0x45, 0xab, 0xe4,
        0x14, 0xc0, 0x10, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0x63, 0xa9, 0x00, 0x06, 0x03, 0x6e,
        0x73, 0x33, 0xc0, 0x10, 0xc0, 0x10, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0x63, 0xa9, 0x00,
        0x06, 0x03, 0x6e, 0x73, 0x31, 0xc0, 0x10, 0xc0, 0x10, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02,
        0x63, 0xa9, 0x00, 0x06, 0x03, 0x6e, 0x73, 0x34, 0xc0, 0x10, 0xc0, 0x10, 0x00, 0x02, 0x00,
        0x01, 0x00, 0x02, 0x63, 0xa9, 0x00, 0x06, 0x03, 0x6e, 0x73, 0x32, 0xc0, 0x10, 0xc0, 0x4e,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x04, 0xf7, 0xa8, 0x00, 0x04, 0xd8, 0xef, 0x20, 0x0a, 0xc0,
        0x4e, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x01, 0x89, 0xa5, 0x00, 0x10, 0x20, 0x01, 0x48, 0x60,
        0x48, 0x02, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0xc0, 0x72, 0x00,
        0x01, 0x00, 0x01, 0x00, 0x04, 0xf7, 0xa8, 0x00, 0x04, 0xd8, 0xef, 0x22, 0x0a, 0xc0, 0x72,
        0x00, 0x1c, 0x00, 0x01, 0x00, 0x01, 0x89, 0xa5, 0x00, 0x10, 0x20, 0x01, 0x48, 0x60, 0x48,
        0x02, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0xc0, 0x3c, 0x00, 0x01,
        0x00, 0x01, 0x00, 0x04, 0xf7, 0xa8, 0x00, 0x04, 0xd8, 0xef, 0x24, 0x0a, 0xc0, 0x3c, 0x00,
        0x1c, 0x00, 0x01, 0x00, 0x00, 0x1e, 0xcf, 0x00, 0x10, 0x20, 0x01, 0x48, 0x60, 0x48, 0x02,
        0x00, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0xc0, 0x60, 0x00, 0x01, 0x00,
        0x01, 0x00, 0x04, 0xf7, 0xa8, 0x00, 0x04, 0xd8, 0xef, 0x26, 0x0a, 0xc0, 0x60, 0x00, 0x1c,
        0x00, 0x01, 0x00, 0x00, 0x1e, 0xcf, 0x00, 0x10, 0x20, 0x01, 0x48, 0x60, 0x48, 0x02, 0x00,
        0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let original = [
        0xa4, 0xac, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x04, 0x00, 0x09, 0x03, 0x77, 0x77,
        0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01,
        0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x40, 0x00, 0x04, 0x45,
        0xab, 0xe4, 0x14, 0xc0, 0x10, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0x63, 0xa9, 0x00, 0x06,
        0x03, 0x6e, 0x73, 0x33, 0xc0, 0x10, 0xc0, 0x10, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0x63,
        0xa9, 0x00, 0x06, 0x03, 0x6e, 0x73, 0x31, 0xc0, 0x10, 0xc0, 0x10, 0x00, 0x02, 0x00, 0x01,
        0x00, 0x02, 0x63, 0xa9, 0x00, 0x06, 0x03, 0x6e, 0x73, 0x34, 0xc0, 0x10, 0xc0, 0x10, 0x00,
        0x02, 0x00, 0x01, 0x00, 0x02, 0x63, 0xa9, 0x00, 0x06, 0x03, 0x6e, 0x73, 0x32, 0xc0, 0x10,
        0xc0, 0x4e, 0x00, 0x01, 0x00, 0x01, 0x00, 0x04, 0xf7, 0xa8, 0x00, 0x04, 0xd8, 0xef, 0x20,
        0x0a, 0xc0, 0x4e, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x01, 0x89, 0xa5, 0x00, 0x10, 0x20, 0x01,
        0x48, 0x60, 0x48, 0x02, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0xc0,
        0x72, 0x00, 0x01, 0x00, 0x01, 0x00, 0x04, 0xf7, 0xa8, 0x00, 0x04, 0xd8, 0xef, 0x22, 0x0a,
        0xc0, 0x72, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x01, 0x89, 0xa5, 0x00, 0x10, 0x20, 0x01, 0x48,
        0x60, 0x48, 0x02, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0xc0, 0x3c,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x04, 0xf7, 0xa8, 0x00, 0x04, 0xd8, 0xef, 0x24, 0x0a, 0xc0,
        0x3c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x1e, 0xcf, 0x00, 0x10, 0x20, 0x01, 0x48, 0x60,
        0x48, 0x02, 0x00, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0xc0, 0x60, 0x00,
        0x01, 0x00, 0x01, 0x00, 0x04, 0xf7, 0xa8, 0x00, 0x04, 0xd8, 0xef, 0x26, 0x0a, 0xc0, 0x60,
        0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x1e, 0xcf, 0x00, 0x10, 0x20, 0x01, 0x48, 0x60, 0x48,
        0x02, 0x00, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x29, 0x10,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let dname = parse_name(&raw, &original);
    assert_eq!(dname.is_ok(), true);
    let dname = dname.unwrap();
    assert_eq!(dname.1.labels.len(), 3);
    assert_eq!(dname.1.to_string(), String::from("www.google.com."));
}

#[test]
fn test_encode_dnsname() {
    // let mut compression: HashMap<String, usize> = HashMap::new();
    let cases = vec![
        (
            "www.baidu.com.",
            vec![
                3, 119, 119, 119, 5, 98, 97, 105, 100, 117, 3, 99, 111, 109, 0,
            ],
        ),
        (
            "www.baidu.com",
            vec![
                3, 119, 119, 119, 5, 98, 97, 105, 100, 117, 3, 99, 111, 109, 0,
            ],
        ),
        (".", vec![0]),
        ("com", vec![3, 99, 111, 109, 0]),
    ];
    for case in cases.into_iter() {
        match DNSName::new(case.0) {
            Ok(name) => {
                let result = name.to_binary(None);
                assert_eq!(result, case.1, "binary array should equal success");
            }
            Err(err) => assert!(false, format!("should return name success: {:?}", err)),
        }
    }
    let mut compression: HashMap<String, usize> = HashMap::new();
    compression.insert("com".to_owned(), 10);
    let cases = vec![
        (
            "www.baidu.com.",
            vec![3, 119, 119, 119, 5, 98, 97, 105, 100, 117, 192, 10],
        ),
        ("www.baidu.com.", vec![192, 20]),
    ];
    for case in cases.into_iter() {
        match DNSName::new(case.0) {
            Ok(name) => {
                let result = name.to_binary(Some((&mut compression, 20)));
                assert_eq!(result, case.1, "binary array should equal success");
            }
            Err(err) => assert!(false, format!("should return name success: {:?}", err)),
        }
    }
}
