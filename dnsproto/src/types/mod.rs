mod a;
mod aaaa;
mod ns;
mod opt;
mod soa;

use super::errors::DNSProtoErr;
use nom::lib::std::collections::HashMap;
use std::fmt::Debug;

pub use a::DnsTypeA;
pub use aaaa::DnsTypeAAAA;
pub use ns::DnsTypeNS;
pub use opt::DNSTypeOpt;
pub use soa::DnsTypeSOA;

// for wireframe convert
pub trait DNSWireFrame: Debug {
    fn encode(
        &self,
        // frame: &mut Cursor<Vec<u8>>,
        compression: Option<(&mut HashMap<String, usize>, usize)>,
    ) -> Result<Vec<u8>, DNSProtoErr>;
}
