// a red-black-tree storage for store all dns data
// use intrusive_collections::{RBTree, intrusive_adapter, RBTreeLink, KeyAdapter};
// use std::cell::Cell;
use crate::errors::StorageError;
use crate::rbtree::RBTree;
use crate::Storage;
use dnsproto::dnsname::DNSName;
use dnsproto::meta::{DNSType, ResourceRecord, RRSet};
use dnsproto::qtype::{DNSWireFrame, DnsTypeSOA};
use std::cell::RefCell;
use std::rc::Rc;
use std::collections::HashMap;


#[derive(Debug)]
struct RBTreeNode {
    label: String,
    rr_sets: HashMap<DNSType, RRSet>,
    
    parent: Option<Rc<RefCell<RBTreeNode>>>,
    subtree: Option<RBTree<String, Rc<RefCell<RBTreeNode>>>>,
}

impl RBTreeNode {
    fn has_type(&self, qtype: DNSType)->bool{
        for (q_type, _) in self.rr_sets.iter() {
            if *q_type == qtype{
                return true;
            }
        }
        false
    }
    fn has_non_type(&self, qtype: DNSType)->bool{
        for (q_type, _) in self.rr_sets.iter() {
            if *q_type != qtype {
                return true;
            }
        }
        false
    }

    pub fn add_rr(&mut self, rr: ResourceRecord) -> Result<(), StorageError>{
        match rr.get_type(){
            DNSType::RRSIG => {
                self.rr_sets.entry(rr.get_type()).or_insert_with(Default::default).add(rr);
            },
            DNSType::CNAME => {
                if self.has_non_type(DNSType::NSEC){
                    return Err(StorageError::AddCNAMEConflictError)
                }
            }
            _ => {
                if self.has_type(DNSType::CNAME) && rr.get_type() != DNSType::NSEC{
                    return Err(StorageError::AddOtherRRConflictCNAME)
                }
                self.rr_sets.entry(rr.get_type()).or_insert_with(Default::default).add(rr);
            }
        }
        Ok(())
    }
    #[allow(dead_code)]
    pub fn get_name(&self) -> DNSName {
        if self.label.is_empty() {
            return DNSName { labels: vec![] };
        }
        let mut labels = vec![];
        labels.push(self.label.clone());
        let mut current = self.parent.clone();
        while let Some(value) = current.clone() {
            let label = (*value.borrow()).label.to_owned();
            if label.is_empty() {
                break;
            }
            labels.push(label);
            current = value.borrow().parent.clone();
        }
        DNSName { labels }
    }
}

#[derive(Debug, Default)]
struct RBTreeStorage {
    root: Option<Rc<RefCell<RBTreeNode>>>,
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
        let mut labels_count = rr.get_label_count();
        let mut current = self.root.clone();
        let mut parent_node = current.clone();
        /// need more better way to iterate item
        let reverse_labels = rr.get_label_iter().rev().cloned();
        for label in reverse_labels {
            labels_count -= 1;
            let mut temp = current.as_ref().unwrap().borrow_mut();
            let subtree = temp.subtree.get_or_insert(RBTree::new());
            let result = subtree.get(&label.clone()).cloned();
            /// subtree exist and has label node
            if let Some(node) = result {
                if labels_count == 0 {
                    node.borrow_mut().add_rr(rr)?;
                    return Ok(());
                }
                drop(temp);
                parent_node = Some(node.clone());
                current = Some(node);
                continue;
            }
            if labels_count == 0 {
                /// subtree exist but has not label node
                /// create a new label node
                let node = Rc::new(RefCell::new(RBTreeNode {
                    label: label.to_string(),
                    rr_sets: Default::default(),
                    parent: parent_node,
                    subtree: None,
                }));
                node.borrow_mut().add_rr(rr)?;
                subtree.insert(
                    label,
                    node,
                );
                return Ok(());
            } else {
                /// create a path to next label, but if each label has a new rbtree will consume
                /// too much memory , so should build with a compressed way
                let create = Rc::new(RefCell::new(RBTreeNode {
                    label: label.to_string(),
                    rr_sets: Default::default(),
                    parent: parent_node,
                    subtree: None,
                }));
                subtree.insert(label.clone(), create.clone());
                drop(temp);
                current = Some(create.clone());
                parent_node = Some(create);
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
mod storage {
    use super::*;
    use dnsproto::meta::DNSClass;
    #[test]
    fn test_rb_node() {
        let node = RBTreeNode {
            label: "baidu".to_string(),
            rr_sets: Default::default(),
            parent: Some(Rc::new(RefCell::new(RBTreeNode {
                label: "com".to_string(),
                rr_sets: Default::default(),
                parent: Some(Rc::new(RefCell::new(RBTreeNode {
                    label: "".to_string(),
                    rr_sets: Default::default(),
                    parent: None,
                    subtree: None,
                }))),
                subtree: None,
            }))),
            subtree: None,
        };
        assert_eq!(node.get_name().to_string(), "baidu.com.".to_owned());
        let node = RBTreeNode {
            label: "".to_string(),
            rr_sets: Default::default(),
            parent: None,
            subtree: None,
        };
        assert_eq!(node.get_name().to_string(), ".".to_owned());
    }
    #[test]
    fn test_rb_storage_insert() {
        let mut storage: RBTreeStorage = Default::default();
        let rr = ResourceRecord::new("baidu.com.", DNSType::A, DNSClass::IN, 1000, None).unwrap();
        storage.insert(rr).unwrap();
        let rr =
            ResourceRecord::new("www.google.com.", DNSType::A, DNSClass::IN, 1000, None).unwrap();
        storage.insert(rr).unwrap();
        let rr = ResourceRecord::new("google.com.", DNSType::NS, DNSClass::IN, 1000, None).unwrap();
        storage.insert(rr).unwrap();
        let rr =
            ResourceRecord::new("www.google.com.", DNSType::NS, DNSClass::IN, 1000, None).unwrap();
        storage.insert(rr).unwrap();
    }

    #[test]
    fn test_node_rr_method(){
        let mut node = RBTreeNode{
            label: "com".to_string(),
            rr_sets: HashMap::new(),
            parent: None,
            subtree: None
        };
        let rr = ResourceRecord::new("google.com.", DNSType::NS, DNSClass::IN, 1000, None).unwrap();
        if let Err(_) = node.add_rr(rr){
            assert!(false)
        }
        let rr = ResourceRecord::new("google.com.", DNSType::SOA, DNSClass::IN, 1000, None).unwrap();
        if let Err(_) = node.add_rr(rr){
            assert!(false)
        }
        let rr = ResourceRecord::new("google.com.", DNSType::CNAME, DNSClass::IN, 1000, None).unwrap();
        if let Err(_) = node.add_rr(rr){
            assert!(true)
        }
    }
}
