// The RDATA of the NSEC RR is as shown below:
//
// 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// /                      Next Domain Name                         /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// /                       Type Bit Maps                           /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// NSEC	aaa. NS SOA RRSIG NSEC DNSKEY

use itertools::enumerate;
use otterlib::errors::{DNSProtoErr, ParseZoneDataErr};

fn decode_nsec_from_bits(input: &[u8]) -> Result<Vec<u16>, ParseZoneDataErr> {
    let mut result = Vec::new();
    let message_size = input.len();
    let mut offset = 0;
    let mut length = 0;
    let mut window = 0;
    let mut last_window = -1;
    while offset < message_size {
        if offset + 2 > message_size {
            return Err(ParseZoneDataErr::GeneralErr(
                "nsec block unpack overflow".to_string(),
            ));
        }
        window = input[offset];
        length = input[offset + 1];
        if window <= last_window {
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
            match block {
                block if block & 0x80 == 0x80 => result.push(window as u16 * 256 + index * 8 + 0),
                block if block & 0x40 == 0x40 => result.push(window as u16 * 256 + index * 8 + 1),
                block if block & 0x20 == 0x20 => result.push(window as u16 * 256 + index * 8 + 2),
                block if block & 0x10 == 0x10 => result.push(window as u16 * 256 + index * 8 + 3),
                block if block & 0x8 == 0x8 => result.push(window as u16 * 256 + index * 8 + 4),
                block if block & 0x4 == 0x4 => result.push(window as u16 * 256 + index * 8 + 5),
                block if block & 0x2 == 0x2 => result.push(window as u16 * 256 + index * 8 + 6),
                block if block & 0x1 == 0x1 => result.push(window as u16 * 256 + index * 8 + 7),
                _ => {}
            }
        }
        offset += length;
        last_window = window;
    }
    Ok(result)
}
fn encode_nsec_from_types(bitmap: Vec<u16>) -> Result<Vec<u8>, ParseZoneDataErr> {
    if bitmap.is_empty() {
        Ok(vec![])
    }
    let mut offset = 0;
    let mut last_window = 0u16;
    let mut last_length = 0u16;
    let mut result = vec![];
    for current in bitmap.iter() {
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
        result[offset] = window as u8;
        result[offset + 1] = length as u8;
        result[offset + 1 + length] |= 1 << (7 - current % 8);
        last_length = length;
        last_window = window;
    }
    offset += last_window + 2;
    Ok(result)
}
