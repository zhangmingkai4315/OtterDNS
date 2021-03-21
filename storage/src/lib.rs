mod rb_storage;
#[macro_use]
mod errors;
mod rbtree;
// mod example;

use dnsproto::dnsname::DNSName;
use dnsproto::meta::{DNSType, ResourceRecord};
use dnsproto::qtype::{DNSWireFrame, DnsTypeSOA};
use errors::StorageError;

trait Storage {
    fn lookup(
        &mut self,
        qtype: DNSType,
        domain: DNSName,
    ) -> Result<Box<dyn DNSWireFrame>, StorageError>;
    // insert will update when the resource record exist already.
    fn insert(&mut self, rr: &ResourceRecord) -> Result<(), StorageError>;
    fn delete(&mut self, qtype: DNSType, domain: &DNSName) -> Result<(), StorageError>;
    fn get_soa(&mut self, domain: &DNSName) -> Result<DnsTypeSOA, StorageError>;
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
