mod soa;
mod a;
mod aaaa;
use std::fmt::Debug;

use super::errors::{PacketProcessErr};
pub use a::DnsTypeA;
pub use aaaa::DnsTypeAAAA;
pub use soa::DnsTypeSOA;




// for wireframe convert
pub trait DNSFrame: Debug{
    type Item;
    fn decode(data: &[u8]) -> Result<Self::Item, PacketProcessErr>;
    fn encode(&self) -> Result<Vec<u8>, PacketProcessErr>;
}
