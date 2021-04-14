mod a;
mod aaaa;
mod cname;
mod dnskey;
mod ds;
mod helper;
mod loc;
mod mx;
mod ns;
mod nsec;
mod nsec3;
mod opt;
mod ptr;
mod rrsig;
mod soa;
mod srv;
mod txt;

use crate::label::Label;
use crate::meta::DNSType;
use crate::qtype::dnskey::DnsTypeDNSKEY;
use crate::qtype::ds::DnsTypeDS;
use crate::qtype::loc::DnsTypeLOC;
use crate::qtype::nsec::DnsTypeNSEC;
use crate::qtype::rrsig::DnsTypeRRSIG;
use crate::qtype::srv::DnsTypeSRV;
use crate::qtype::txt::DnsTypeTXT;
pub use a::DnsTypeA;
pub use aaaa::DnsTypeAAAA;
pub use cname::DnsTypeCNAME;
pub use mx::DnsTypeMX;
use nom::lib::std::collections::HashMap;
use nom::lib::std::fmt::Display;
pub use ns::DnsTypeNS;
pub use opt::DnsTypeOpt;
use otterlib::errors::DNSProtoErr;
pub use ptr::DnsTypePTR;
pub use soa::DnsTypeSOA;
use std::any::Any;
use std::fmt::Debug;
use std::str::FromStr;

type CompressionType<'a> = Option<(&'a mut HashMap<Vec<Label>, usize>, usize)>;

pub trait DNSWireFrame: Debug + Display {
    fn decode(data: &[u8], _: Option<&[u8]>) -> Result<Self, DNSProtoErr>
    where
        Self: Sized;
    fn get_type(&self) -> DNSType;
    fn encode(
        &self,
        // frame: &mut Cursor<Vec<u8>>,
        compression: CompressionType,
    ) -> Result<Vec<u8>, DNSProtoErr>;
    fn as_any(&self) -> &dyn Any;
}

pub fn decode_message_data<'a>(
    data: &'a [u8],
    original: &'a [u8],
    dtype: DNSType,
) -> Result<Box<dyn DNSWireFrame>, DNSProtoErr> {
    // A NS CNAME MX TXT PTR SOA AAAA LOC SRV OPT DS DNSKEY NSEC
    match dtype {
        DNSType::A => match DnsTypeA::decode(data, None) {
            Ok(val) => Ok(Box::new(val)),
            _ => Err(DNSProtoErr::PacketParseError),
        },
        DNSType::NS => match DnsTypeNS::decode(data, Some(original)) {
            Ok(val) => Ok(Box::new(val)),
            _ => Err(DNSProtoErr::PacketParseError),
        },
        DNSType::CNAME => match DnsTypeCNAME::decode(data, Some(original)) {
            Ok(val) => Ok(Box::new(val)),
            _ => Err(DNSProtoErr::PacketParseError),
        },
        DNSType::MX => match DnsTypeMX::decode(data, Some(original)) {
            Ok(val) => Ok(Box::new(val)),
            _ => Err(DNSProtoErr::PacketParseError),
        },
        DNSType::TXT => match DnsTypeTXT::decode(data, Some(original)) {
            Ok(val) => Ok(Box::new(val)),
            _ => Err(DNSProtoErr::PacketParseError),
        },
        DNSType::PTR => match DnsTypePTR::decode(data, Some(original)) {
            Ok(val) => Ok(Box::new(val)),
            _ => Err(DNSProtoErr::PacketParseError),
        },
        DNSType::SOA => match DnsTypeSOA::decode(data, Some(original)) {
            Ok(val) => Ok(Box::new(val)),
            _ => Err(DNSProtoErr::PacketParseError),
        },
        DNSType::AAAA => match DnsTypeAAAA::decode(data, Some(original)) {
            Ok(val) => Ok(Box::new(val)),
            _ => Err(DNSProtoErr::PacketParseError),
        },
        DNSType::LOC => match DnsTypeLOC::decode(data, None) {
            Ok(val) => Ok(Box::new(val)),
            _ => Err(DNSProtoErr::PacketParseError),
        },
        DNSType::SRV => match DnsTypeSRV::decode(data, None) {
            Ok(val) => Ok(Box::new(val)),
            _ => Err(DNSProtoErr::PacketParseError),
        },
        DNSType::OPT => match DnsTypeOpt::decode(data, None) {
            Ok(val) => Ok(Box::new(val)),
            _ => Err(DNSProtoErr::PacketParseError),
        },
        DNSType::DS => match DnsTypeDS::decode(data, None) {
            Ok(val) => Ok(Box::new(val)),
            _ => Err(DNSProtoErr::PacketParseError),
        },
        DNSType::RRSIG => match DnsTypeRRSIG::decode(data, Some(original)) {
            Ok(val) => Ok(Box::new(val)),
            _ => Err(DNSProtoErr::PacketParseError),
        },
        DNSType::DNSKEY => match DnsTypeDNSKEY::decode(data, None) {
            Ok(val) => Ok(Box::new(val)),
            _ => Err(DNSProtoErr::PacketParseError),
        },
        DNSType::NSEC => match DnsTypeNSEC::decode(data, Some(original)) {
            Ok(val) => Ok(Box::new(val)),
            _ => Err(DNSProtoErr::PacketParseError),
        },
        _ => Err(DNSProtoErr::UnImplementedError(format!(
            "dns type {} unknown",
            dtype
        ))),
    }
}
// TODO: Update Decode From String
pub fn decode_dns_data_from_string(
    original_string: &str,
    dtype: DNSType,
    default_original: Option<&str>,
) -> Result<Box<dyn DNSWireFrame>, DNSProtoErr> {
    // A NS CNAME MX TXT PTR SOA AAAA LOC SRV OPT[unimpl] DS DNSKEY NSEC
    let original_string = original_string.replace(|c| c == '(' || c == ')', "");
    let original_string = original_string.trim_matches(|c| c == ' ' || c == '\"');
    match dtype {
        DNSType::A => match DnsTypeA::from_str(original_string) {
            Ok(dtype) => Ok(Box::new(dtype)),
            Err(err) => Err(err),
        },
        DNSType::NS => match DnsTypeNS::from_str(original_string, default_original) {
            Ok(dtype) => Ok(Box::new(dtype)),
            Err(err) => Err(err),
        },
        DNSType::CNAME => match DnsTypeCNAME::from_str(original_string, default_original) {
            Ok(dtype) => Ok(Box::new(dtype)),
            Err(err) => Err(err),
        },
        DNSType::MX => match DnsTypeMX::from_str(original_string, default_original) {
            Ok(dtype) => Ok(Box::new(dtype)),
            Err(err) => Err(err),
        },
        DNSType::TXT => match DnsTypeTXT::from_str(original_string) {
            Ok(dtype) => Ok(Box::new(dtype)),
            Err(err) => Err(err),
        },
        DNSType::PTR => match DnsTypePTR::from_str(original_string, default_original) {
            Ok(dtype) => Ok(Box::new(dtype)),
            Err(err) => Err(err),
        },
        DNSType::SOA => match DnsTypeSOA::from_str(original_string, default_original) {
            Ok(dtype) => Ok(Box::new(dtype)),
            Err(err) => Err(err),
        },
        DNSType::LOC => match DnsTypeLOC::from_str(original_string) {
            Ok(dtype) => Ok(Box::new(dtype)),
            Err(err) => Err(err),
        },
        DNSType::AAAA => match DnsTypeAAAA::from_str(original_string) {
            Ok(dtype) => Ok(Box::new(dtype)),
            Err(err) => Err(err),
        },
        DNSType::SRV => match DnsTypeSRV::from_str(original_string, default_original) {
            Ok(dtype) => Ok(Box::new(dtype)),
            Err(err) => Err(err),
        },
        DNSType::RRSIG => match DnsTypeRRSIG::from_str(original_string) {
            Ok(dtype) => Ok(Box::new(dtype)),
            Err(err) => Err(err),
        },
        DNSType::DS => match DnsTypeDS::from_str(original_string) {
            Ok(dtype) => Ok(Box::new(dtype)),
            Err(err) => Err(err),
        },
        DNSType::DNSKEY => match DnsTypeDNSKEY::from_str(original_string) {
            Ok(dtype) => Ok(Box::new(dtype)),
            Err(err) => Err(err),
        },
        DNSType::NSEC => match DnsTypeNSEC::from_str(original_string, default_original) {
            Ok(dtype) => Ok(Box::new(dtype)),
            Err(err) => Err(err),
        },
        _ => Err(DNSProtoErr::UnImplementedError(format!(
            "dns type {} unknown",
            dtype
        ))),
    }
}
