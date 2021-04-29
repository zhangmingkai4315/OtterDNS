#![allow(unused_doc_comments)]
mod rbtree;
pub mod unsafe_rbtree;
#[macro_use]
pub mod safe_rbtree;
pub mod storage;
// mod example;

use dnsproto::dnsname::DNSName;
use dnsproto::meta::{DNSType, ResourceRecord};
use dnsproto::qtype::{DNSWireFrame, DnsTypeSOA};
use otterlib::errors::StorageError;

trait Storage {
    fn lookup(
        &mut self,
        qtype: DNSType,
        domain: DNSName,
    ) -> Result<Box<dyn DNSWireFrame>, StorageError>;
    // insert will update when the resource record exist already.
    fn insert(&mut self, rr: ResourceRecord) -> Result<(), StorageError>;
    fn delete(&mut self, qtype: DNSType, domain: &DNSName) -> Result<(), StorageError>;
    fn get_soa(&mut self, domain: DNSName) -> Result<DnsTypeSOA, StorageError>;
}
