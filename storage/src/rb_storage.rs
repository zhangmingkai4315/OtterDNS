// a red-black-tree storage for store all dns data
// use intrusive_collections::{RBTree, intrusive_adapter, RBTreeLink, KeyAdapter};
// use std::cell::Cell;
use crate::errors::StorageError;
use crate::rbtree::RBTree;
use crate::Storage;
use dnsproto::dnsname::DNSName;
use dnsproto::errors::DNSProtoErr;
use dnsproto::meta::{DNSClass, DNSType, ResourceRecord};
use dnsproto::qtype::{DNSWireFrame, DnsTypeSOA};
use std::borrow::BorrowMut;
use std::cell::RefCell;
use std::ops::Deref;
use std::thread::current;

#[derive(Debug)]
struct RBTreeNode {
    label: String,
    data: Vec<ResourceRecord>,
    subtree: Option<RBTree<String, RBTreeNode>>,
}
#[derive(Debug)]
struct RBTreeStorage {
    root: RBTreeNode,
}

impl RBTreeStorage {
    fn new() -> RBTreeStorage {
        RBTreeStorage {
            root: RBTreeNode {
                label: "".to_owned(),
                data: vec![],
                subtree: None,
            },
        }
    }
}

impl Storage for RBTreeStorage {
    fn lookup(
        &mut self,
        qtype: DNSType,
        domain: DNSName,
    ) -> Result<Box<dyn DNSWireFrame>, StorageError> {
        unimplemented!()
    }

    fn insert(&mut self, rr: &ResourceRecord) -> Result<(), StorageError> {
        let mut labels = rr.get_labels()?;
        let ref mut subtree = self.root.subtree;
        let mut found = false;
        for i in rr.name.labels.iter().rev() {
            if subtree.is_none() {
                break;
            }
            let mut result = subtree.unwrap();
            let mut result = result.get(i);
            if result.is_none() {
                break;
            }
            let next_subtree = result.take();
            subtree = next_subtree.unwrap().subtree;
        }
        Ok(())
    }

    fn delete(&mut self, qtype: DNSType, domain: &DNSName) -> Result<(), StorageError> {
        unimplemented!()
    }

    fn get_soa(&mut self, domain: &DNSName) -> Result<DnsTypeSOA, StorageError> {
        unimplemented!()
    }
}
