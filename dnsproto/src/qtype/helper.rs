use crate::dnsname::DNSName;
use crate::meta::DNSType;
use crate::qtype::ds::DigestType;
use itertools::enumerate;
use nom::bytes::complete::is_not;
use nom::error::Error;
use otterlib::errors::{DNSProtoErr, ParseZoneDataErr};
use std::fmt::Write;

pub fn not_space(str: &str) -> Result<(&str, &str), ParseZoneDataErr> {
    match is_not::<_, _, Error<&str>>(" \t\r\n")(str) {
        Err(err) => Err(ParseZoneDataErr::ParseDNSFromStrError(err.to_string())),
        Ok(val) => Ok(val),
    }
}

pub fn hex_u8_to_string(input: &[u8]) -> String {
    let mut result = String::with_capacity(2 * input.len());
    for &byte in input {
        let _ = write!(&mut result, "{:02X}", byte);
    }
    result
}

pub fn string_to_hex_u8(input: &str) -> Result<Vec<u8>, ParseZoneDataErr> {
    (0..input.len())
        .step_by(2)
        .map(|i| match u8::from_str_radix(&input[i..i + 2], 16) {
            Ok(val) => Ok(val),
            _ => Err(ParseZoneDataErr::GeneralErr(format!(
                "ds digest string to hex u8 fail : {}",
                input
            ))),
        })
        .collect()
}

pub fn nsec_bits_to_string(input: &[u8]) -> Result<String, ParseZoneDataErr> {
    decode_nsec_from_bits(input).map(|result| {
        result
            .iter()
            .map(|v| {
                DNSType::from_u16(*v)
                    .unwrap_or(DNSType::Unknown)
                    .to_string()
            })
            .collect::<Vec<String>>()
            .join(" ")
    })
}

pub fn decode_nsec_from_bits(input: &[u8]) -> Result<Vec<u16>, ParseZoneDataErr> {
    let mut result = Vec::new();
    let message_size = input.len();
    let mut offset = 0;
    let mut length: usize;
    let mut window: u8;
    let mut last_window = -1;
    while offset < message_size {
        if offset + 2 > message_size {
            return Err(ParseZoneDataErr::GeneralErr(
                "nsec block unpack overflow".to_string(),
            ));
        }
        window = input[offset];
        length = input[offset + 1] as usize;
        offset += 2;
        if window as isize <= last_window {
            return Err(ParseZoneDataErr::GeneralErr(
                "nsec block unpack out of order".to_string(),
            ));
        }
        if length == 0 {
            return Err(ParseZoneDataErr::GeneralErr(
                "nsec block is empty".to_string(),
            ));
        }
        if length > 32 {
            return Err(ParseZoneDataErr::GeneralErr(
                "nsec block too long".to_string(),
            ));
        }
        if offset + length > message_size {
            return Err(ParseZoneDataErr::GeneralErr(
                "nsec block unpack overflow".to_string(),
            ));
        }
        for (index, block) in enumerate(input[offset..offset + length].iter()) {
            let index = index as u16;
            if block & 0x80 == 0x80 {
                result.push(window as u16 * 256 + index * 8)
            }
            if block & 0x40 == 0x40 {
                result.push(window as u16 * 256 + index * 8 + 1)
            }
            if block & 0x20 == 0x20 {
                result.push(window as u16 * 256 + index * 8 + 2)
            }
            if block & 0x10 == 0x10 {
                result.push(window as u16 * 256 + index * 8 + 3)
            }
            if block & 0x8 == 0x8 {
                result.push(window as u16 * 256 + index * 8 + 4)
            }
            if block & 0x4 == 0x4 {
                result.push(window as u16 * 256 + index * 8 + 5)
            }
            if block & 0x2 == 0x2 {
                result.push(window as u16 * 256 + index * 8 + 6)
            }
            if block & 0x1 == 0x1 {
                result.push(window as u16 * 256 + index * 8 + 7)
            }
        }
        offset += length;
        last_window = window as isize;
    }
    Ok(result)
}
pub fn encode_nsec_from_types(bitmap: Vec<DNSType>) -> Result<Vec<u8>, ParseZoneDataErr> {
    if bitmap.is_empty() {
        return Ok(vec![]);
    }
    let mut offset = 0;
    let mut last_window = 0u16;
    let mut last_length = 0u16;
    let mut result = vec![];
    for current in bitmap.iter() {
        let current = *current as u16;
        let window = current / 256;
        let length = (current - window * 256) / 8 + 1;
        if window > last_window && last_length != 0 {
            offset += last_length + 2;
            last_length = 0;
        }
        if window < last_window || length < last_length {
            return Err(ParseZoneDataErr::GeneralErr(
                "nsec bit out of order".to_string(),
            ));
        }
        let expected_length = (offset + 2 + length) as usize;
        if expected_length > result.len() {
            result.resize(expected_length, 0);
        }
        result[offset as usize] = window as u8;
        result[(offset + 1) as usize] = length as u8;
        result[(offset + 1 + length) as usize] |= 1 << (7 - current % 8);
        last_length = length;
        last_window = window;
    }
    // offset += last_window + 2;
    Ok(result)
}

pub fn hash_dname(
    name: &str,
    ds: DigestType,
    iter: u16,
    salt: &[u8],
) -> Result<Vec<u8>, DNSProtoErr> {
    match ds {
        DigestType::SHA1 => {
            let name = DNSName::new(name, None)?;
            let name_binary = name.to_binary(None);
            let mut buffer = name_binary;
            for _ in 0..iter {
                let mut context =
                    ring::digest::Context::new(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY);
                context.update(buffer.as_slice());
                context.update(salt);
                buffer = context.finish().as_ref().to_vec();
            }
            Ok(buffer.to_vec())
        }
        _ => Err(DNSProtoErr::UnImplementedError(
            "unknown hash algorithem for nsec3".to_owned(),
        )),
    }
}

#[cfg(test)]
mod test {
    use crate::qtype::ds::DigestType;
    use crate::qtype::helper::hash_dname;

    #[test]
    fn test_hash_dname() {
        let salt: Vec<u8> = vec![0x4c, 0xd7, 0xb0, 0x54, 0xf8, 0x76, 0x95, 0x6c];
        let result = hash_dname("google.com.", DigestType::SHA1, 5, salt.as_slice());
        assert_eq!(result.is_ok(), true);
        let result = result.unwrap();
        assert_eq!(
            result,
            vec![
                98, 146, 27, 123, 115, 74, 243, 32, 48, 234, 185, 42, 165, 37, 200, 84, 124, 185,
                235, 187
            ]
            .as_slice()
        );
    }
}
