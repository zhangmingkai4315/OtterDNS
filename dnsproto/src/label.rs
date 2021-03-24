#![allow(unused_doc_comments)]
use crate::errors::ParseZoneDataErr;
use crate::utils::valid_label;
use itertools::EitherOrBoth::{Both, Left, Right};
use itertools::Itertools;
use nom::lib::std::fmt::Formatter;
use nom::AsChar;
use std::cmp::Ordering;
use std::fmt::Display;
use std::str::FromStr;

#[derive(Eq, PartialEq, Hash)]
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

impl Display for Label {
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
