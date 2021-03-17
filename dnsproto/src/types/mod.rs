mod a;
mod aaaa;
mod ns;
mod soa;

use super::errors::DNSProtoErr;
use nom::lib::std::collections::HashMap;
use std::fmt::Debug;

pub use a::DnsTypeA;
pub use aaaa::DnsTypeAAAA;
pub use ns::DnsTypeNS;
pub use soa::DnsTypeSOA;

// for wireframe convert
pub trait DNSWireFrame: Debug {
    fn encode(
        &self,
        compression: Option<(&mut HashMap<String, usize>, usize)>,
    ) -> Result<Vec<u8>, DNSProtoErr>;
}
