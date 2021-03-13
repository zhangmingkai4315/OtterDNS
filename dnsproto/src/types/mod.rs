mod a;
mod aaaa;
mod soa;
use std::fmt::Debug;

use super::errors::DNSProtoErr;
pub use a::DnsTypeA;
pub use aaaa::DnsTypeAAAA;
pub use soa::DnsTypeSOA;

// for wireframe convert
pub trait DNSFrame: Debug {
    type Item;
    fn decode(data: &[u8]) -> Result<Self::Item, DNSProtoErr>;
    fn encode(&self) -> Result<Vec<u8>, DNSProtoErr>;
}
