use nom::character::complete::multispace0;
use nom::number::complete::{be_u32, be_u8, double};
// use std::any::Any;
use crate::meta::DNSType;
use crate::qtype::{CompressionType, DNSWireFrame};
use otterlib::errors::DNSProtoErr;
use std::any::Any;
use std::fmt;
use std::fmt::Formatter;
use std::str::FromStr;

named!( parse_lat<&str,&str>, alt!( tag!( "S" ) | tag!( "s" ) | tag!( "N" ) | tag!( "n" ) ) );
named!( parse_lng<&str,&str>, alt!( tag!( "E" ) | tag!( "W" ) ) );
static DEFAULT_SIZE_HP_VP: [u8; 3] = [0x12, 0x16, 0x13];

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

impl FromStr for DnsTypeLOC {
    type Err = DNSProtoErr;
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
                        return Err(DNSProtoErr::ParseDNSFromStrError(str.to_owned()));
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
                        return Err(DNSProtoErr::ParseDNSFromStrError(str.to_owned()));
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
        if val.is_empty() {
            return Err(DNSProtoErr::ParseDNSFromStrError(
                "loc record must have altitude infomation".to_owned(),
            ));
        }
        let alt_str = val[0];
        let alt = translate_loc_alt_to_u32(alt_str)?;
        let mut additional_u8 = [0, 0, 0];
        let mut iter_index = 0;
        for inner in &val[1..] {
            let temp = translate_loc_additiona_to_u8(inner)?;
            additional_u8[iter_index] = temp;
            iter_index += 1;
        }

        for inner in 0..3 {
            if inner < iter_index {
                continue;
            }
            additional_u8[inner] = DEFAULT_SIZE_HP_VP[inner]
        }
        Ok(DnsTypeLOC {
            version: 0,
            size: additional_u8[0],
            hor_precision: additional_u8[1],
            ver_precision: additional_u8[2],
            lat: translate_loc_lat_to_u32(lat, lat_label)?,
            lon: translate_loc_lng_to_u32(lng, lng_label)?,
            alt,
        })
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
    fn get_size(&self) -> String {
        format!("{:.2}m", Self::get_addtional(self.size))
    }
    fn get_horizpre(&self) -> String {
        format!("{:.2}m", Self::get_addtional(self.hor_precision))
    }
    fn get_vertpre(&self) -> String {
        format!("{:.2}m", Self::get_addtional(self.ver_precision))
    }
    fn get_altitude(&self) -> String {
        format!("{:.2}m", (self.alt as f64) / 100.0 - 100000.0)
    }
    fn get_addtional(additional: u8) -> f64 {
        let mut size = 0.01 * ((additional >> 4 & 0xf) as f64);
        let mut count = additional & 0xf;
        loop {
            if count == 0 {
                break;
            }
            size *= 10.0;
            count -= 1;
        }
        size
    }
    fn get_lat_and_lng(&self) -> (String, String) {
        let lat = (self.lat as i64 - (1 << 31)) as f64 / 3600000.0;
        let remlat = 60.0 * (lat - (lat as i64) as f64);

        let lng = (self.lon as i64 - (1 << 31)) as f64 / 3600000.0;
        let remlng = 60.0 * (lng - (lng as i64) as f64);
        let lat_label = match lat > 0.0 {
            true => "N".to_owned(),
            false => "S".to_owned(),
        };
        let lng_label = match lng > 0.0 {
            true => "E".to_owned(),
            false => "W".to_owned(),
        };
        (
            format!(
                "{} {} {} {}",
                (lat as i64).abs(),
                (remlat as i64).abs(),
                ((((remlat - (remlat as i64) as f64) * 60.0) as f64)
                    .round()
                    .abs()),
                lat_label
            ),
            format!(
                "{} {} {} {}",
                (lng as i64).abs(),
                (remlng as i64).abs(),
                ((((remlng - (remlng as i64) as f64) * 60.0) as f64)
                    .round()
                    .abs()),
                lng_label
            ),
        )
    }
}

impl fmt::Display for DnsTypeLOC {
    fn fmt(&self, format: &mut Formatter<'_>) -> fmt::Result {
        let location = self.get_lat_and_lng();
        write!(
            format,
            "{} {} {} {} {} {}",
            location.0,
            location.1,
            self.get_altitude(),
            self.get_size(),
            self.get_horizpre(),
            self.get_vertpre()
        )
    }
}

impl DNSWireFrame for DnsTypeLOC {
    fn decode(data: &[u8], original: Option<&[u8]>) -> Result<Self, DNSProtoErr> {
        match parse_loc(data, original.unwrap_or(&[])) {
            Ok((_, soa)) => Ok(soa),
            Err(_err) => Err(DNSProtoErr::PacketParseError),
        }
    }

    fn get_type(&self) -> DNSType {
        DNSType::LOC
    }

    fn encode(&self, _: CompressionType) -> Result<Vec<u8>, DNSProtoErr>
    where
        Self: Sized,
    {
        let mut data = vec![];
        data.extend_from_slice(&self.version.to_be_bytes()[..]);
        data.extend_from_slice(&self.size.to_be_bytes()[..]);
        data.extend_from_slice(&self.hor_precision.to_be_bytes()[..]);
        data.extend_from_slice(&self.ver_precision.to_be_bytes()[..]);
        data.extend_from_slice(&self.lat.to_be_bytes()[..]);
        data.extend_from_slice(&self.lon.to_be_bytes()[..]);
        data.extend_from_slice(&self.alt.to_be_bytes()[..]);
        Ok(data)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn translate_loc_lat_to_u32(val: [f64; 3], label: &str) -> Result<u32, DNSProtoErr> {
    if val[0] >= 90.00 || val[1] >= 60.00 || val[2] >= 60.00 {
        return Err(DNSProtoErr::ParseDNSFromStrError(
            "loc translate error".to_owned(),
        ));
    }
    let latitude =
        (1000.0 * 60.0 * 60.0 * val[0] + (1000.0 * 60.0 * val[1]) + (1000.0 * val[2])) as u32;
    if latitude > 90 * 1000 * 60 * 60 {
        return Err(DNSProtoErr::ParseDNSFromStrError(
            "loc overflow error".to_owned(),
        ));
    }
    match label {
        "s" | "S" => Ok((1u32 << 31) - latitude),
        "n" | "N" => Ok((1u32 << 31) + latitude),
        _ => Err(DNSProtoErr::ParseDNSFromStrError(
            "unknow loc label error".to_owned(),
        )),
    }
}

fn translate_loc_lng_to_u32(val: [f64; 3], label: &str) -> Result<u32, DNSProtoErr> {
    if val[0] >= 180.00 || val[1] >= 60.00 || val[2] >= 60.00 {
        return Err(DNSProtoErr::ParseDNSFromStrError(
            "loc translate error".to_owned(),
        ));
    }
    let longitude =
        ((1000.0 * 60.0 * 60.0 * val[0]) + (1000.0 * 60.0 * val[1]) + (1000.0 * val[2])) as u32;
    if longitude > 180 * 1000 * 60 * 60 {
        return Err(DNSProtoErr::ParseDNSFromStrError(
            "loc overflow error".to_owned(),
        ));
    }
    match label {
        "e" | "E" => Ok(longitude + (1u32 << 31)),
        "w" | "W" => Ok((1u32 << 31) - longitude),
        _ => Err(DNSProtoErr::ParseDNSFromStrError(
            "unknow loc label error".to_owned(),
        )),
    }
}

fn translate_loc_alt_to_u32(val: &str) -> Result<u32, DNSProtoErr> {
    let val = val.trim_end_matches(|c| c == 'm' || c == 'M');
    match f64::from_str(val) {
        Ok(val) => {
            if !(-100000.00..=42849672.95).contains(&val) {
                return Err(DNSProtoErr::ParseDNSFromStrError(
                    "out of alt range error".to_owned(),
                ));
            }
            Ok((100_f64 * val + 10000000.0 + 0.5) as u32)
        }
        _ => Err(DNSProtoErr::ParseDNSFromStrError(
            "unknown loc record alt".to_owned(),
        )),
    }
}

fn translate_loc_additiona_to_u8(val: &str) -> Result<u8, DNSProtoErr> {
    let val = val.trim_end_matches(|c| c == 'm' || c == 'M');
    let val = val.split('.').collect::<Vec<&str>>();
    let mut val_size = val.len();
    let mut e_: u8;
    let m_: u8;
    let mut metre = 0;
    let mut cmeter = 0;
    let mut result: i32;
    if val_size == 0 {
        return Err(DNSProtoErr::ParseDNSFromStrError(
            "parse loc a error".to_owned(),
        ));
    }
    if val_size == 2 {
        match i32::from_str(val[1]) {
            Ok(temp) => cmeter = temp,
            Err(_) => {
                return Err(DNSProtoErr::ParseDNSFromStrError(
                    "parse loc a error".to_owned(),
                ))
            }
        }
        val_size -= 1;
    }
    if val_size == 1 {
        match i32::from_str(val[0]) {
            Ok(temp) => metre = temp,
            Err(_) => {
                return Err(DNSProtoErr::ParseDNSFromStrError(
                    "parse loc a error".to_owned(),
                ))
            }
        }
    }
    if metre > 0 {
        e_ = 2;
        result = metre;
    } else {
        e_ = 0;
        result = cmeter;
    }
    while result >= 10 {
        e_ += 1;
        result /= 10;
    }
    if e_ > 9 {
        return Err(DNSProtoErr::ParseDNSFromStrError(
            "parse loc out of range".to_owned(),
        ));
    }
    m_ = result as u8;
    Ok(e_ & 0x0f | m_ << 4 & 0xf0)
}

#[cfg(test)]
mod test {
    use crate::qtype::loc::{translate_loc_additiona_to_u8, DnsTypeLOC};
    use crate::qtype::DNSWireFrame;
    use std::str::FromStr;

    #[test]
    fn test_loc_from_str() {
        let cases = [
            (
                // dig loc caida.org @8.8.8.8
                "32 53 1.000 N 117 14 25.000 W 107.00m 30m 10m 10m",
                DnsTypeLOC::new(0, 0x33, 0x13, 0x13, 2265864648, 1725418648, 10010700).unwrap(),
            ),
            (
                // dig loc ckdhr.com @8.8.8.8
                "42 21 43.528 N 71 5 6.284 W -25.00m 1m 3000m 10m",
                DnsTypeLOC::new(0, 0x12, 0x35, 0x13, 2299987176, 1891577364, 9997500).unwrap(),
            ),
            (
                // dig loc alink.net @8.8.8.8
                "37 22 26.000 N 122 1 47.000 W 30.00m 30m 30m 10m",
                DnsTypeLOC::new(0, 0x33, 0x33, 0x13, 2282029648, 1708176648, 10003000).unwrap(),
            ),
        ];
        for test_case in cases.iter() {
            let loc = DnsTypeLOC::from_str(test_case.0);
            assert_eq!(loc.is_ok(), true);
            assert_eq!(loc.unwrap(), test_case.1)
        }
    }

    #[test]
    fn test_translate_loc_additiona_to_u8() {
        let input = [
            ("30m", 0x33),  // 51
            ("30M", 0x33),  // 51
            ("30", 0x33),   // 51
            ("10m", 0x13),  // 19
            ("3000", 0x35), // 53
        ];
        for i in input.iter() {
            assert_eq!(translate_loc_additiona_to_u8(i.0), Ok(i.1));
        }
    }
    #[test]
    fn test_format_loc_to_string() {
        //  "32 53 1.000 N 117 14 25.000 W 107.00m 30m 10m 10m",
        let loc = DnsTypeLOC::new(0, 0x33, 0x13, 0x13, 2265864648, 1725418648, 10010700).unwrap();
        assert_eq!(
            loc.get_lat_and_lng(),
            ("32 53 1 N".to_owned(), "117 14 25 W".to_owned())
        );
        assert_eq!(loc.get_size(), "30.00m".to_string());
        assert_eq!(loc.get_horizpre(), "10.00m".to_string());
        assert_eq!(loc.get_vertpre(), "10.00m".to_string());
        assert_eq!(loc.get_altitude(), "107.00m".to_string());
        assert_eq!(
            loc.to_string(),
            "32 53 1 N 117 14 25 W 107.00m 30.00m 10.00m 10.00m"
        )
    }

    #[test]
    fn test_dns_type_loc() {
        let input = [
            0x00, 0x12, 0x35, 0x13, 0x89, 0x17, 0x04, 0xe8, 0x70, 0xbf, 0x2e, 0x14, 0x00, 0x98,
            0x8c, 0xbc,
        ];
        let loc_example =
            DnsTypeLOC::new(0, 0x12, 0x35, 0x13, 2299987176, 1891577364, 9997500).unwrap();
        match DnsTypeLOC::decode(&input, None) {
            Ok(loc) => {
                assert_eq!(loc, loc_example)
            }
            _ => {
                assert!(false)
            }
        }
        match loc_example.encode(None) {
            Ok(binary_encoded) => {
                assert_eq!(binary_encoded.as_slice(), input)
            }
            _ => {
                assert!(false)
            }
        }
    }
}
