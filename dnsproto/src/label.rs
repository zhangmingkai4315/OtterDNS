#![allow(unused_doc_comments)]
use crate::errors::ParseZoneDataErr;
use crate::utils::is_safe_ascii;
use itertools::EitherOrBoth::{Both, Left, Right};
use itertools::Itertools;
use nom::lib::std::fmt::Formatter;
use nom::AsChar;
use std::cmp::Ordering;
use std::fmt::Display;
use std::hash::{Hash, Hasher};
use std::str::FromStr;
#[derive(Debug, Clone)]
pub struct Label(Vec<u8>);

impl Hash for Label {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for i in self.0.iter() {
            if *i >= 65 && *i <= 90 {
                (*i + 32u8).hash(state);
            } else {
                (*i).hash(state);
            }
        }
    }
}

impl FromStr for Label {
    type Err = ParseZoneDataErr;
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if !valid_label(input) {
            return Err(ParseZoneDataErr::ParseDNSFromStrError(input.to_owned()));
        }
        match format_rfc4343_label(input) {
            Some(val) => Ok(Label(val)),
            _ => Err(ParseZoneDataErr::ParseDNSFromStrError(input.to_string())),
        }
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
impl Eq for Label {}

impl PartialEq for Label {
    fn eq(&self, other: &Self) -> bool {
        for it in self.0.iter().zip_longest(other.0.iter()) {
            match it {
                Both(left, right) => match Label::compare_label(*left, *right) {
                    Ordering::Equal => continue,
                    _ => return false,
                },
                Left(_) => return false,
                Right(_) => return false,
            }
        }
        true
    }
}
impl Ord for Label {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).unwrap()
    }
}
impl PartialOrd for Label {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        for it in self.0.iter().zip_longest(other.0.iter()) {
            match it {
                Both(left, right) => match Label::compare_label(*left, *right) {
                    Ordering::Equal => continue,
                    result => return Some(result),
                },
                Left(_) => return Some(Ordering::Greater),
                Right(_) => return Some(Ordering::Less),
            }
        }
        Some(Ordering::Equal)
    }
}

impl Label {
    pub fn root() -> Label {
        Label(vec![])
    }
    pub fn from_vec(input: Vec<u8>) -> Label {
        Label(input)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn compare_label(mut left: u8, mut right: u8) -> Ordering {
        if (0x61..=0x7A).contains(&left) {
            left -= 0x20;
        }
        if (0x61..=0x7A).contains(&right) {
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

/// format_rfc4343_label will check the label is valid label for rfc4343 and format
/// the label, translate the text label to binary array
/// for example : hello\.world will save as hello.world no more escape.
pub fn format_rfc4343_label(label: &str) -> Option<Vec<u8>> {
    let mut token = false;
    let mut number_bucket = 2;
    let mut number = [0u8, 0u8, 0u8];
    let mut result = vec![];
    for i in label.as_bytes() {
        if *i == 92 && !token {
            // i == "\"
            token = true;
            continue;
        }
        if token {
            if *i >= 48 && *i <= 57 {
                // i = [0, 9] is number
                if number_bucket > 0 {
                    number[3 - number_bucket - 1] = *i - 48;
                    number_bucket -= 1;
                } else {
                    number[2] = *i - 48;
                    let number_value = number[0] * 100 + number[1] * 10 + number[2];
                    if number_value <= 0x20 || number_value >= 0x7f {
                        result.push(number_value);
                        token = false;
                    } else {
                        return None;
                    }
                }
                continue;
            } else if *i == 46 || *i == 92 {
                // i == "." || i == "\"
                if !token {
                    return None;
                } else {
                    token = false;
                }
            } else {
                return None;
            }
        }
        result.push(*i);
    }
    if token {
        return None;
    }
    Some(result)
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
    use crate::utils::calculate_hash;
    #[test]
    fn test_label_fn() {
        let label = Label::from_str("hello");
        assert_eq!(label.is_ok(), true);
        let label = label.unwrap();
        assert_eq!(label.len(), 5);
        assert_eq!(label.is_empty(), false);
        assert_eq!(label.to_string(), "hello");
        let label2 = Label::from_str("heLLo").unwrap();
        assert_eq!(label == label2, true);
    }
    #[test]
    fn test_abnormal_label_fn() {
        let label = Label::from_str("hello\\.bai");
        assert_eq!(label.is_ok(), true);
        let label = label.unwrap();
        assert_eq!(label.len(), 9);
        assert_eq!(label.is_empty(), false);
        assert_eq!(label.to_string(), "hello\\.bai");
        let label2 = Label::from_str("heLLo\\.bai").unwrap();
        assert_eq!(label == label2, true);
    }

    #[test]
    fn test_format_rfc4343_label() {
        // \. \\ and  \[000-032] and \[127-255]
        assert_eq!(
            format_rfc4343_label("hello\\.world").is_some(),
            true,
            "hello\\.world"
        );
        assert_eq!(
            format_rfc4343_label("hello\\000").is_some(),
            true,
            "hello\\000"
        );
        assert_eq!(
            format_rfc4343_label("hello\\023").is_some(),
            true,
            "hello\\023"
        );
        assert_eq!(
            format_rfc4343_label("hello\\097").is_some(),
            false,
            "hello\\097"
        );
        assert_eq!(
            format_rfc4343_label("hello\\\\").is_some(),
            true,
            "hello\\\\"
        );
        assert_eq!(
            format_rfc4343_label("hello\\020").is_some(),
            true,
            "hello\\020"
        );
        assert_eq!(
            format_rfc4343_label("hello\\ world").is_none(),
            true,
            "hello\\ world"
        );
        assert_eq!(
            format_rfc4343_label("hello\\.0"),
            Some("hello.0".as_bytes().to_vec()),
            "hello\\.0"
        );
        assert_eq!(
            format_rfc4343_label("hello\\0ab").is_none(),
            true,
            "hello\\0ab"
        );
    }

    #[test]
    fn test_label_hash() {
        let tests = vec![
            ("hello", "hEllo", true),
            ("hello\\.world", "heLLO\\.world", true),
        ];
        for (l1, l2, status) in tests {
            let h1 = calculate_hash(&Label::from_str(l1).unwrap());
            let h2 = calculate_hash(&Label::from_str(l2).unwrap());
            assert_eq!(h1 == h2, status)
        }
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
