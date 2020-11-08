use std::net::{Ipv4Addr, Ipv6Addr};
use crate::dns::errors::{ParseRRErr};
use std::str::FromStr;
use std::error::Error;


#[derive(Debug, PartialOrd, PartialEq)]
struct DNS_A(Ipv4Addr);

impl DNS_A{
    fn from_binary(data: [u8;4]) -> DNS_A{
        return DNS_A(Ipv4Addr::from(data))
    }
    fn to_binary(&self) -> [u8;4]{
        self.0.octets()
    }
}

impl FromStr for DNS_A{
    type Err = ParseRRErr;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.parse::<Ipv4Addr>() {
            Ok(v) => return Ok(DNS_A(v)),
            Err(e) => return Err(ParseRRErr::from(e)),
        }
    }
}

#[test]
fn test_dnstype_a(){
    assert_eq!(DNS_A::from_binary([0,0,0,0]), DNS_A(Ipv4Addr::new(0,0,0,0)));
    assert_eq!(DNS_A::from_binary([127,0,0,1]), DNS_A(Ipv4Addr::new(127,0,0,1)));
    assert_eq!(DNS_A::from_binary([255,255,255,255]), DNS_A(Ipv4Addr::new(255,255,255,255)));

    assert_eq!("1.2.3.4".parse::<DNS_A>().unwrap(), DNS_A::from_binary([1,2,3,4]));
    assert_eq!("192.168.1.1".parse::<DNS_A>().unwrap(), DNS_A::from_binary([192,168,1,1]));
    assert_eq!("127.0.0.1".parse::<DNS_A>().unwrap(), DNS_A::from_binary([127,0,0,1]));
    assert_eq!("255.255.255.0".parse::<DNS_A>().unwrap(), DNS_A::from_binary([255,255,255,0]));

    assert_eq!("1.2.3".parse::<DNS_A>().unwrap_err(),ParseRRErr::ParseTypeErr("invalid IP address syntax".to_owned()));
    assert_eq!("".parse::<DNS_A>().unwrap_err(),ParseRRErr::ParseTypeErr("invalid IP address syntax".to_owned()));
    assert_eq!("256.256.265.23".parse::<DNS_A>().unwrap_err(),ParseRRErr::ParseTypeErr("invalid IP address syntax".to_owned()));
    assert_eq!("-1.-1.-2.-3".parse::<DNS_A>().unwrap_err(),ParseRRErr::ParseTypeErr("invalid IP address syntax".to_owned()));

    assert_eq!("1.2.3.4".parse::<DNS_A>().unwrap().to_binary(), [1,2,3,4]);
    assert_eq!("192.168.1.1".parse::<DNS_A>().unwrap().to_binary(), [192,168,1,1]);
    assert_eq!("127.0.0.1".parse::<DNS_A>().unwrap().to_binary(), [127,0,0,1]);
    assert_eq!("255.255.255.0".parse::<DNS_A>().unwrap().to_binary(), [255,255,255,0]);
}


#[derive(Debug, PartialOrd, PartialEq)]
struct DNS_AAAA(Ipv6Addr);

impl DNS_AAAA{
    fn from_binary(data: [u8;16]) -> DNS_AAAA{
        return DNS_AAAA(Ipv6Addr::from(data))
    }
    fn to_binary(&self) -> [u8;16]{
        self.0.octets()
    }
}

impl FromStr for DNS_AAAA{
    type Err = ParseRRErr;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.parse::<Ipv6Addr>() {
            Ok(v) => return Ok(DNS_AAAA(v)),
            Err(e) => return Err(ParseRRErr::from(e)),
        }
    }
}

#[test]
fn test_dnstype_aaaa(){
    assert_eq!(DNS_AAAA::from_binary([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), DNS_AAAA(Ipv6Addr::from_str("::").unwrap()));
    assert_eq!(DNS_AAAA::from_binary([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1]), DNS_AAAA(Ipv6Addr::from_str("::127.0.0.1").unwrap()));
    assert_eq!(DNS_AAAA::from_binary([255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 64, 32]), DNS_AAAA(Ipv6Addr::from_str("FF00::192.168.64.32").unwrap()));

    assert_eq!(DNS_AAAA::from_binary([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), "::".parse::<DNS_AAAA>().unwrap());
    assert_eq!(DNS_AAAA::from_binary([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1]), "::127.0.0.1".parse::<DNS_AAAA>().unwrap());
    assert_eq!(DNS_AAAA::from_binary([255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 64, 32]), "FF00::192.168.64.32".parse::<DNS_AAAA>().unwrap());

    assert_eq!("1.2.3".parse::<DNS_AAAA>().unwrap_err(),ParseRRErr::ParseTypeErr("invalid IP address syntax".to_owned()));
    assert_eq!("::::".parse::<DNS_AAAA>().unwrap_err(),ParseRRErr::ParseTypeErr("invalid IP address syntax".to_owned()));
    assert_eq!("FF00::192.168.64.32::".parse::<DNS_AAAA>().unwrap_err(),ParseRRErr::ParseTypeErr("invalid IP address syntax".to_owned()));
    assert_eq!("::127.0.0.1::".parse::<DNS_AAAA>().unwrap_err(),ParseRRErr::ParseTypeErr("invalid IP address syntax".to_owned()));

}
