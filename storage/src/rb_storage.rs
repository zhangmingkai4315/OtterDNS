// a red-black-tree storage for store all dns data
// use intrusive_collections::{RBTree, intrusive_adapter, RBTreeLink, KeyAdapter};
// use std::cell::Cell;
use crate::errors::StorageError;
use crate::rbtree::RBTree;
use crate::Storage;
use dnsproto::dnsname::DNSName;
use dnsproto::meta::{DNSClass, DNSType, ResourceRecord};
use dnsproto::qtype::{DNSWireFrame, DnsTypeSOA};
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Debug)]
struct RBTreeNode {
    label: String, 
    data: Vec<ResourceRecord>,
    parent: Option<Rc<RefCell<RBTreeNode>>>,
    subtree: Option<RBTree<String, Rc<RefCell<RBTreeNode>>>>,
}

impl RBTreeNode{
    fn get_name(&self) -> String{
        let mut name = self.label.clone();
        let mut current = self.parent.clone();
        loop{
            match current.clone(){
                Some(value) => {
                    name = ".".to_string() + &*value.borrow().label;
                    current = value.borrow().parent.clone();
                },
                _ => {
                    break;
                }
            }
        }
        name

    }
}

#[derive(Debug)]
struct RBTreeStorage {
    root: Option<Rc<RefCell<RBTreeNode>>>,
}

impl RBTreeStorage {
    fn new() -> RBTreeStorage {
        RBTreeStorage {
            root: Some(Rc::new(RefCell::new(RBTreeNode {
                label: "".to_string(),
                data: vec![],
                parent: None,
                subtree: None,
            }))),
        }
    }
}

impl Storage for RBTreeStorage {
    fn lookup(
        &mut self,
        _qtype: DNSType,
        _domain: DNSName,
    ) -> Result<Box<dyn DNSWireFrame>, StorageError> {
        Err(StorageError::StorageNotReadyError)
    }

    fn insert(&mut self, rr: ResourceRecord) -> Result<(), StorageError> {
        let mut labels_count = rr.name.label_count();
        let mut current = self.root.clone();
        let mut parent_node = current.clone();
        for i in rr.name.labels.iter().rev() {
            labels_count -= 1;
            let mut temp = current.as_ref().unwrap().borrow_mut();
            let subtree = temp.subtree.get_or_insert(RBTree::new());
            let result = subtree.get(&i.clone()).cloned();
            if let Some(node) = result {
                if labels_count == 0 {
                    node.borrow_mut().data.push(rr);
                    return Ok(());
                }

                drop(temp);
                parent_node = Some(node.clone());
                current = Some(node);
            }else{
                if labels_count == 0 {
                    subtree.insert(
                        i.clone(),
                        Rc::new(RefCell::new(RBTreeNode {
                            label: i.to_string(),
                            data: vec![rr],
                            parent: parent_node.clone(),
                            subtree: None,
                        })),
                    );
                    return Ok(());
                } else {
                    let create = Rc::new(RefCell::new(RBTreeNode {
                        label: i.to_string(),
                        data: vec![],
                        parent: parent_node.clone(),
                        subtree: None,
                    }));
                    subtree.insert(
                        i.clone(),
                        create.clone(),
                    );
                    drop(temp);
                    current = Some(create.clone());
                    parent_node = Some(create.clone());
                }
            }
        }
        Ok(())
    }

    fn delete(&mut self, _qtype: DNSType, _domain: &DNSName) -> Result<(), StorageError> {
        unimplemented!()
    }

    fn get_soa(&mut self, _domain: DNSName) -> Result<DnsTypeSOA, StorageError> {
        unimplemented!()
    }
}
#[cfg(test)]
mod storage{
    use super::*;
    #[test]
    fn test_rb_node(){
        let node = RBTreeNode{
            label: "baidu".to_string(),
            data: vec![],
            parent: Some(Rc::new(RefCell::new(RBTreeNode{
                label: "com".to_string(),
                data: vec![],
                parent:  Some(Rc::new(RefCell::new(RBTreeNode{
                    label: "".to_string(),
                    data: vec![],
                    parent:  None,
                    subtree: None
                }))),
                subtree: None
            }))),
            subtree: None
        };
        assert_eq!(node.get_name(), "baidu.com".to_owned());
    }
    #[test]
    fn test_rb_storage_insert() {
        let mut storage = RBTreeStorage::new();
        // let meminfo = sys_info::mem_info().unwrap();
        // print!("{:?}\n", meminfo);
        let rr = ResourceRecord::new("baidu.com.", DNSType::A, DNSClass::IN, 1000, None).unwrap();
        storage.insert(rr).unwrap();
        let rr = ResourceRecord::new("www.google.com.", DNSType::A, DNSClass::IN, 1000, None).unwrap();
        storage.insert(rr).unwrap();
        let rr = ResourceRecord::new("google.com.", DNSType::NS, DNSClass::IN, 1000, None).unwrap();
        storage.insert(rr).unwrap();
        let rr = ResourceRecord::new("www.google.com.", DNSType::NS, DNSClass::IN, 1000, None).unwrap();
        storage.insert(rr).unwrap();
    }

}
