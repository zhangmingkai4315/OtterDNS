use crate::dnsname::{parse_name, DNSName};
use crate::errors::{DNSProtoErr, ParseZoneDataErr};
use crate::meta::DNSType;
use crate::qtype::{CompressionType, DNSWireFrame};
use nom::bytes::complete::{tag, take_while};
use nom::character::complete::{digit1, multispace0};
use nom::combinator::rest;
use nom::number::complete::{be_u32, be_u8, double};
use std::any::Any;
use std::fmt;
use std::fmt::Formatter;
use std::str::FromStr;

#[derive(Debug, PartialEq)]
pub struct DnsTypeLOC {
    version: u8,
    size: u8,
    hor_precision: u8,
    ver_precision: u8,
    lat: u32,
    lon: u32,
    alt: u32,
}

// <owner> <TTL> <class> LOC ( d1 [m1 [s1]] {"N"|"S"} d2 [m2 [s2]]
// {"E"|"W"} alt["m"] [siz["m"] [hp["m"]
// [vp["m"]]]] )
// d1:     [0 .. 90]            (degrees latitude)
// d2:     [0 .. 180]           (degrees longitude)
// m1, m2: [0 .. 59]            (minutes latitude/longitude)
// s1, s2: [0 .. 59.999]        (seconds latitude/longitude)
// alt:    [-100000.00 .. 42849672.95] BY .01 (altitude in meters)
// siz, hp, vp: [0 .. 90000000.00] (size/precision in meters)

// Example:
// 52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m
// 52 N 4 E -2.00m 0.00m 10000m 10m
// 31.000 N 106 28 29.000 W 10.00m 1m 10000m 10m

// The size defaults to one meter, which is perfect for a single host.
// Horizontal precision defaults to 10,000 meters, and vertical precision
// to 10 meters.

named!( parse_lat<&str,&str>, alt!( tag!( "S" ) | tag!( "s" ) | tag!( "N" ) | tag!( "n" ) ) );
named!( parse_lng<&str,&str>, alt!( tag!( "E" ) | tag!( "W" ) ) );
static DEFAULT_SIZE_HP_VP: [u8; 4] = [0x00, 0x12, 0x16, 0x13];

fn translate_loc_lat_to_u32(val: [f64; 3], label: &str) -> Result<u32, ParseZoneDataErr> {
    if val[0] >= 90.00 || val[1] >= 60.00 || val[2] >= 60.00 {
        return Err(ParseZoneDataErr::ParseDNSFromStrError(
            "loc translate error".to_owned(),
        ));
    }
    let latitude =
        1000 * 60 * 60 * (val[0] as u32) + 1000 * 60 * (val[1] as u32) + 1000 * (val[2] as u32);
    if latitude > 90 * 1000 * 60 * 60 {
        return Err(ParseZoneDataErr::ParseDNSFromStrError(
            "loc overflow error".to_owned(),
        ));
    }
    return match label {
        "s" | "S" => Ok(latitude + 1 << 31),
        "n" | "N" => Ok(1 << 31 - latitude),
        _ => Err(ParseZoneDataErr::ParseDNSFromStrError(
            "unknow loc label error".to_owned(),
        )),
    };
}

fn translate_loc_lng_to_u32(val: [f64; 3], label: &str) -> Result<u32, ParseZoneDataErr> {
    if val[0] >= 180.00 || val[1] >= 60.00 || val[2] >= 60.00 {
        return Err(ParseZoneDataErr::ParseDNSFromStrError(
            "loc translate error".to_owned(),
        ));
    }
    let longitude =
        1000 * 60 * 60 * (val[0] as u32) + 1000 * 60 * (val[1] as u32) + 1000 * (val[2] as u32);
    if longitude > 180 * 1000 * 60 * 60 {
        return Err(ParseZoneDataErr::ParseDNSFromStrError(
            "loc overflow error".to_owned(),
        ));
    }
    return match label {
        "e" | "E" => Ok(longitude + 1 << 31),
        "w" | "W" => Ok(1 << 31 - longitude),
        _ => Err(ParseZoneDataErr::ParseDNSFromStrError(
            "unknow loc label error".to_owned(),
        )),
    };
}

fn translate_loc_alt_to_u32(val: f64) -> Result<u32, ParseZoneDataErr> {
    if val < -100000.00 || val > 42849672.95 {
        return Err(ParseZoneDataErr::ParseDNSFromStrError(
            "out of alt range error".to_owned(),
        ));
    }
    Ok((100 as f64 * val + 100000000.0 + 0.5) as u32)
}

fn translate_loc_additiona_to_u8(val: f64) -> Result<u8, ParseZoneDataErr> {
    Ok(0u8)
}

impl FromStr for DnsTypeLOC {
    type Err = ParseZoneDataErr;
    fn from_str(str: &str) -> Result<Self, Self::Err> {
        let mut lng = [0.0, 0.0, 0.0];
        let mut index = 0;
        let mut lat = [0.0, 0.0, 0.0];
        let mut current = str;
        let lat_label = loop {
            let (rest, _) = multispace0(current)?;
            let (rest, lat_val) = double(rest)?;
            lat[index] = lat_val;
            let (rest, _) = multispace0(rest)?;
            match parse_lat(rest) {
                Ok((rest, is_lat)) => {
                    if !is_lat.is_empty() {
                        current = rest;
                        break is_lat;
                    } else {
                        index += 1;
                        current = rest
                    }
                    if index == 3 {
                        return Err(ParseZoneDataErr::ParseDNSFromStrError(str.to_owned()));
                    }
                }
                _ => {
                    index += 1;
                    current = rest;
                    continue;
                }
            }
        };
        let mut index = 0;
        let lng_label = loop {
            let (rest, _) = multispace0(current)?;
            let (rest, lng_val) = double(rest)?;
            lng[index] = lng_val;
            let (rest, _) = multispace0(rest)?;
            match parse_lng(rest) {
                Ok((rest, is_lat)) => {
                    if !is_lat.is_empty() {
                        current = rest;
                        break is_lat;
                    } else {
                        index += 1;
                        current = rest
                    }
                    if index == 3 {
                        return Err(ParseZoneDataErr::ParseDNSFromStrError(str.to_owned()));
                    }
                }
                _ => {
                    index += 1;
                    current = rest;
                    continue;
                }
            }
        };

        let val = current
            .split_whitespace()
            .into_iter()
            .collect::<Vec<&str>>();
        // let mut additional: [f64; 4] = [0.0, 0, 0, 0];
        let mut additional_u8 = [0u8, 0, 0, 0];
        let mut iter_index = 0;
        for inner in val {
            match f64::from_str(inner.trim_end_matches("m")) {
                Ok(val) => {
                    // additional[iter_index] = val;
                    additional_u8[iter_index] = translate_loc_additiona_to_u8(val)?;
                    iter_index += 1;
                }
                Err(err) => return Err(ParseZoneDataErr::ParseDNSFromStrError(err.to_string())),
            }
        }

        for inner in 0..=3 {
            if inner < iter_index {
                continue;
            }
            additional_u8[inner] = DEFAULT_SIZE_HP_VP[inner]
        }
        //TODO: write a function to turn 1000m => 0x13 => 1 * 10 ^3
        // so the input is a f64 but output is u8

        //TODO: write a function turn lat and label into lat:u32
        // write a function turn lng and label into lng:u32
        // write a function turn alt f64 into u32
        Ok(DnsTypeLOC {
            version: 0,
            size: 0,
            hor_precision: 0,
            ver_precision: 0,
            lat: translate_loc_lat_to_u32(lat, lat_label)?,
            lon: translate_loc_lng_to_u32(lng, lng_label)?,
            alt: 0,
        })
    }
}

#[test]
fn test_loc_from_str() {
    let cases = [
        "52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m",
        "52 N 4 E -2.00m 0.00m 10000m 10m",
        "31.000 N 106 28 29.000 W 10.00m 1m 10000m 10m",
    ];
    for test_case in cases.iter() {
        let loc = DnsTypeLOC::from_str(test_case);
        assert_eq!(loc.is_ok(), true);
    }
}

named_args!(parse_loc<'a>(original: &[u8])<DnsTypeLOC>,
    do_parse!(
        version: be_u8>>
        size: be_u8>>
        hor_precision: be_u8>>
        ver_precision: be_u8>>
        lat: be_u32>>
        lon: be_u32>>
        alt: be_u32>>
        (DnsTypeLOC{
            version,
            size,
            hor_precision,
            ver_precision,
            lat,
            lon,
            alt,
        }
    )
));

#[allow(clippy::too_many_arguments)]
impl DnsTypeLOC {
    pub fn new(
        version: u8,
        size: u8,
        hor_precision: u8,
        ver_precision: u8,
        lat: u32,
        lon: u32,
        alt: u32,
    ) -> Result<Self, DNSProtoErr> {
        Ok(DnsTypeLOC {
            version,
            size,
            hor_precision,
            ver_precision,
            lat,
            lon,
            alt,
        })
    }
}

impl fmt::Display for DnsTypeLOC {
    fn fmt(&self, format: &mut Formatter<'_>) -> fmt::Result {
        write!(format, "{} {} {}", self.lat, self.lon, self.alt,)
    }
}
