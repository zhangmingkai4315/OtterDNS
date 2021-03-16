mod a;
mod aaaa;
mod ns;
mod soa;

use std::fmt::Debug;

use super::errors::DNSProtoErr;
pub use a::DnsTypeA;
pub use aaaa::DnsTypeAAAA;
use nom::lib::std::collections::HashMap;
pub use soa::DnsTypeSOA;

// for wireframe convert
pub trait DNSWireFrame: Debug {
    type Item;
    fn decode(data: &[u8], original: Option<&[u8]>) -> Result<Self::Item, DNSProtoErr>;
    fn encode(
        &self,
        compression: Option<(&mut HashMap<String, usize>, usize)>,
    ) -> Result<Vec<u8>, DNSProtoErr>;
}
