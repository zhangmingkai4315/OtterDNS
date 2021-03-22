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
use std::cell::RefCell;
use std::ops::Deref;
use std::rc::Rc;
use std::thread::current;
// use sys_info::MemInfo;

#[derive(Debug)]
struct RBTreeNode {
    data: Vec<ResourceRecord>,
    subtree: RBTree<String, Rc<RefCell<RBTreeNode>>>,
}
#[derive(Debug)]
struct RBTreeStorage {
    root: Option<Rc<RefCell<RBTreeNode>>>,
}

impl RBTreeStorage {
    fn new() -> RBTreeStorage {
        RBTreeStorage {
            root: Some(Rc::new(RefCell::new(RBTreeNode {
                data: vec![],
                subtree: Default::default(),
            }))),
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

    fn insert(&mut self, rr: ResourceRecord) -> Result<(), StorageError> {
        let mut labels_count = rr.get_labels()?;
        let mut current = self.root.clone();
        for i in rr.name.labels.iter().rev() {
            labels_count -= 1;
            let temp = current.as_ref().unwrap();
            let result = temp.borrow_mut().subtree.get(&i.clone()).cloned();
            if result.is_none() {
                if labels_count == 0 {
                    temp.borrow_mut().subtree.insert(
                        i.clone(),
                        Rc::new(RefCell::new(RBTreeNode {
                            data: vec![rr],
                            subtree: Default::default(),
                        })),
                    );
                    return Ok(());
                } else {
                    let create = Rc::new(RefCell::new(RBTreeNode {
                        data: vec![],
                        subtree: Default::default(),
                    }));
                    temp.borrow_mut().subtree.insert(i.clone(), create.clone());
                    current = Some(create.clone());
                }
            } else {
                if labels_count == 0 {
                    result.unwrap().borrow_mut().data.push(rr);
                    return Ok(());
                }
                current = result;
            }
        }
        Ok(())
    }

    fn delete(&mut self, qtype: DNSType, domain: &DNSName) -> Result<(), StorageError> {
        unimplemented!()
    }

    fn get_soa(&mut self, domain: DNSName) -> Result<DnsTypeSOA, StorageError> {
        unimplemented!()
    }
}

#[test]
fn test_rb_storage_insert() {
    let mut storage = RBTreeStorage::new();
    // let meminfo = sys_info::mem_info().unwrap();
    // print!("{:?}\n", meminfo);
    let rr = ResourceRecord::new("baidu.com.", DNSType::A, DNSClass::IN, 1000, None).unwrap();
    storage.insert(rr);
    let rr = ResourceRecord::new("www.google.com.", DNSType::A, DNSClass::IN, 1000, None).unwrap();
    storage.insert(rr);
    let rr = ResourceRecord::new("google.com.", DNSType::NS, DNSClass::IN, 1000, None).unwrap();
    storage.insert(rr);
    let rr = ResourceRecord::new("www.google.com.", DNSType::NS, DNSClass::IN, 1000, None).unwrap();
    storage.insert(rr);
    // let meminfo = sys_info::mem_info().unwrap();
    // print!("{:?}\n", meminfo);
    println!("{:?}", storage);
}
