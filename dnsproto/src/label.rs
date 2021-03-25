#![allow(unused_doc_comments)]
use crate::errors::ParseZoneDataErr;
use crate::utils::is_safe_ascii;
use itertools::EitherOrBoth::{Both, Left, Right};
use itertools::Itertools;
use nom::lib::std::fmt::Formatter;
use nom::AsChar;
use std::cmp::Ordering;
use std::fmt::Display;
use std::hash::Hasher;
use std::str::FromStr;

#[derive(Hash, PartialOrd, PartialEq)]
struct Label(Vec<u8>);

impl FromStr for Label {
    type Err = ParseZoneDataErr;
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if !valid_label(input) {
            return Err(ParseZoneDataErr::ParseDNSFromStrError(input.to_owned()));
        }

        Ok(Label(input.as_bytes().to_vec()))
    }
}
impl Display for Label {
    /// format for rfc4343
    fn fmt(&self, format: &mut Formatter) -> std::fmt::Result {
        let mut output = String::new();
        for &i_u8 in self.0.iter() {
            if i_u8 <= 0x20 || i_u8 >= 0x7f {
                output.push('\\');
                output += format!("{:03}", i_u8).as_str();
            } else {
                /// 46 = '.'  92 == '\'
                if i_u8 == 46 || i_u8 == 92 {
                    output.push('\\');
                }
                output.push(i_u8.as_char());
            }
        }
        write!(format, "{}", output)
    }
}

impl Label {
    fn size(&self) -> usize {
        self.0.len()
    }
    fn empty(&self) -> bool {
        self.0.is_empty()
    }

    fn compare_label(mut left: u8, mut right: u8) -> Ordering {
        if left >= 0x61 && left <= 0x7A {
            left -= 0x20;
        }
        if right >= 0x61 && right <= 0x7A {
            right -= 0x20;
        }
        if left < right {
            return Ordering::Less;
        }
        if left > right {
            return Ordering::Greater;
        }
        Ordering::Equal
    }
}

pub fn is_rfc4343_allowed_label(label: &str) -> bool {
    let mut token = false;
    let mut number_bucket = 2;
    let mut number = [0u8, 0u8, 0u8];
    for i in label.as_bytes() {
        if *i == 92 && token == false {
            // i == "\"
            token = true;
            continue;
        }
        if token == true {
            if *i >= 48 && *i <= 57 {
                // i = [0, 9] is number
                if number_bucket > 0 {
                    number[3 - number_bucket - 1] = *i - 48;
                    number_bucket -= 1;
                } else {
                    number[2] = *i - 48;
                    println!("{:?}", number);
                    let number_value = number[0] * 100 + number[1] * 10 + number[2];
                    if number_value <= 0x20 || number_value >= 0x7f {
                        token = false;
                    } else {
                        return false;
                    }
                }
                continue;
            } else if *i == 46 || *i == 92 {
                // i == "." || i == "\"
                if token == false {
                    return false;
                } else {
                    token == false;
                }
            } else {
                return false;
            }
        }
        token = false
    }
    if token == true {
        return false;
    }
    true
}

#[test]
fn test_is_rfc4343_allowed_label() {
    // \. \\ and  \[000-032] and \[127-255]
    assert_eq!(
        is_rfc4343_allowed_label("hello\\.world"),
        true,
        "hello\\.world"
    );
    assert_eq!(is_rfc4343_allowed_label("hello\\000"), true, "hello\\000");
    assert_eq!(is_rfc4343_allowed_label("hello\\023"), true, "hello\\023");
    assert_eq!(is_rfc4343_allowed_label("hello\\097"), false, "hello\\097");
    assert_eq!(is_rfc4343_allowed_label("hello\\\\"), true, "hello\\\\");
    assert_eq!(is_rfc4343_allowed_label("hello\\020"), true, "hello\\020");
    assert_eq!(
        is_rfc4343_allowed_label("hello\\ world"),
        false,
        "hello\\ world"
    );
    assert_eq!(is_rfc4343_allowed_label("hello\\.0"), true, "hello\\.0");
    assert_eq!(is_rfc4343_allowed_label("hello\\0ab"), false, "hello\\0ab");
}

pub fn valid_label(label: &str) -> bool {
    label.len() <= 63
        && !label.is_empty()
        && label.is_ascii()
        && label.chars().take(1).all(|c| is_safe_ascii(c, true))
        && label.chars().skip(1).all(|c| is_safe_ascii(c, false))
}

#[cfg(test)]
mod label {
    use super::*;
    #[test]
    fn test_label_fn() {
        let label = Label::from_str("hello");
        assert_eq!(label.is_ok(), true);
        let label = label.unwrap();
        assert_eq!(label.size(), 5);
        assert_eq!(label.empty(), false);
        assert_eq!(label.to_string(), "hello");
        let label2 = Label::from_str("heLLo").unwrap();
        assert_eq!(label == label2, true);
    }
    #[test]
    fn test_abnormal_label_fn() {
        let label = Label::from_str("hello\\.bai");
        assert_eq!(label.is_ok(), true);
        let label = label.unwrap();
        assert_eq!(label.size(), 10);
        assert_eq!(label.empty(), false);
        assert_eq!(label.to_string(), "hello");
        let label2 = Label::from_str("heLLo\\.bai").unwrap();
        assert_eq!(label == label2, true);
    }

    #[test]
    fn test_valid_label() {
        assert_eq!(valid_label("hello"), true);
        assert_eq!(valid_label("_hello"), true);
        assert_eq!(valid_label("12hello"), true);
        assert_eq!(valid_label("*"), true);

        // https://tools.ietf.org/html/rfc4343
        assert_eq!(valid_label("hello\\.world"), true);
        assert_eq!(valid_label("hello\\032"), true);
        assert_eq!(valid_label("xn--abc"), true);
        assert_eq!(valid_label("%hello"), false);
        assert_eq!(valid_label("he%llo"), false);
        assert_eq!(
            valid_label(std::str::from_utf8(&[65_u8; 88]).unwrap()),
            false
        );
    }
}
