use crate::errors::ParseZoneDataErr;
use nom::bytes::complete::is_not;
use nom::error::Error;

pub fn not_space(str: &str) -> Result<(&str, &str), ParseZoneDataErr> {
    match is_not::<_, _, Error<&str>>(" \t\r\n")(str) {
        Err(err) => Err(ParseZoneDataErr::ParseDNSFromStrError(err.to_string())),
        Ok(val) => Ok(val),
    }
}
