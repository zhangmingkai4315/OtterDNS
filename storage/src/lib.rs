#[macro_use]
extern crate intrusive_collections;

mod rb_storage;
#[macro_use]
mod errors;
mod rbtree;


use dnsproto::qtype::{self, DNSWireFrame, DnsTypeSOA};
use dnsproto::meta::{self, DNSType, ResourceRecord};
use dnsproto::dnsname::DNSName;

trait Storage{
    fn lookup(qtype: DNSType, domain: DNSName)->Result<Box<dyn DNSWireFrame>, errors::StorageError>;
    // insert will update when the resource record exist already.
    fn insert(rr: &ResourceRecord)->bool;
    fn delete(qtype: DNSType, domain: &DNSName) -> Result<(), errors::StorageError>;
    fn get_soa(domain: &DNSName)->Result<DnsTypeSOA, errors::StorageError>;
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
