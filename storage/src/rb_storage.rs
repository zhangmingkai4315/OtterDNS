// a red-black-tree storage for store all dns data
// use intrusive_collections::{RBTree, intrusive_adapter, RBTreeLink, KeyAdapter};
// use std::cell::Cell;
use crate::errors::StorageError;
use crate::rbtree::{RBTree, TreeIterator};
// use crate::Storage;
use dnsproto::dnsname::DNSName;
use dnsproto::meta::{DNSType, RRSet, ResourceRecord};
// use dnsproto::qtype::{DNSWireFrame, DnsTypeSOA};
use dnsproto::label::Label;
use lazy_static::lazy_static;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::{Rc, Weak};
use std::str::FromStr;
use std::ops::Deref;
use std::borrow::{Borrow, BorrowMut};
// use std::iter::IntoIterator;
use std::vec::IntoIter;

lazy_static! {
    static ref WILDCARD_LABEL: Label = Label::from_str("*").unwrap();
}

#[derive(Debug)]
pub struct RBTreeNode {
    label: Label,
    rr_sets: HashMap<DNSType, RRSet>,
    parent: RefCell<Weak<RefCell<RBTreeNode>>>,
    subtree: Option<RBTree<Label, Rc<RefCell<RBTreeNode>>>>,
}

#[derive(Debug)]
pub struct RBZone(Rc<RefCell<RBTreeNode>>);

impl RBZone{
    fn iter(&self) -> ZoneIter {
        ZoneIter{
            stack: vec![self.0.clone()],
            iter: None
        }
    }
}

struct ZoneIter<'a>{
    stack: Vec<Rc<RefCell<RBTreeNode>>>,
    iter: Option<TreeIterator<'a , Label, Rc<RefCell<RBTreeNode>>>>
}



impl<'a> Iterator for ZoneIter<'a>{
    type Item = Rc<RefCell<RBTreeNode>>;

    fn next(&mut self) -> Option<Self::Item> {
        loop{
            if let Some(node) =  &mut self.iter {
                if let Some(o) = node.next() {
                    return Some(o.1.clone());
                }
                self.iter = None;
            }
            if self.stack.is_empty() {
                return None
            }
            // let node = self.stack.pop().unwrap().clone();
            // if let Some(v) = &(*node).borrow_mut().subtree{
            //     self.iter = Some(v.into_iter());
            // }
        }
    }
}




impl RBZone {
    pub fn from_node(node: RBTreeNode) -> RBZone {
        RBZone {
            0: Rc::new(RefCell::new(node)),
        }
    }
    pub fn new_root() -> RBZone {
        let root = RBTreeNode {
            label: Label::root(),
            rr_sets: Default::default(),
            parent: RefCell::new(Default::default()),
            subtree: None,
        };
        RBZone(Rc::new(RefCell::new(root)))
    }
    /// locate the dns name node from top zone root node. if the dns name is not found in this zone
    /// create a sub node based the label.
    /// should valid if the name is below to the zone data.
    pub fn find_or_insert(&self, name: &DNSName) -> Rc<RefCell<RBTreeNode>> {
        let mut labels_count = name.label_count();
        if labels_count == 0 {
            return self.0.clone();
        }
        let mut current = self.0.clone();
        let mut parent_node = current.clone();
        for label in name.labels.iter().rev() {
            labels_count -= 1;
            let mut clone = current.clone();
            let mut temp = clone.deref().borrow_mut();
            let subtree = temp.subtree.get_or_insert(RBTree::new());

            let result = subtree.get(&label.clone()).cloned();
            /// subtree exist and has label node
            if let Some(node) = result {
                if labels_count == 0 {
                    return node;
                }
                parent_node = node.clone();
                current = node;
                continue;
            }
            /// not found in subtree
            if labels_count == 0 {
                /// subtree exist but has not label node
                /// create a new label node
                let node = RBTreeNode::from_label(label.clone());
                *(*node).borrow_mut().parent.borrow_mut() = Rc::downgrade(&parent_node);
                // (*node).parent.borrow_mut() = Rc::downgrade(&parent_node);
                subtree.insert(label.clone(), node.clone());
                return node;
            } else {
                /// create a path to next label, but if each label has a new rbtree will consume
                /// too much memory , so should build with a compressed way
                let create = RBTreeNode::from_label(label.clone());
                *(*create).borrow_mut().parent.borrow_mut() = Rc::downgrade(&parent_node);
                subtree.insert(label.clone(), create.clone());
                current = create.clone();
                parent_node = create;
            }
        }
        current
    }

    // pub fn find_v2(&self, name: &DNSName) -> Result<ZoneInfo, StorageError>{
    //
    //     Err(StorageError::Unimplemented)
    // }

    /// find the dns name node from top zone root node. if the dns name is not found return Err
    /// otherwise return Node, do not create any new node
    pub fn find(&self, name: &DNSName) -> Result<Rc<RefCell<RBTreeNode>>, StorageError> {
        let mut labels_count = name.label_count();
        if labels_count == 0 {
            return Ok(self.0.clone());
        }
        let mut current = self.0.clone();
        for label in name.labels.iter().rev() {
            labels_count -= 1;
            let mut clone = current.clone();
            let mut temp = clone.deref().borrow_mut();
            /// domain is not a zone, just include itself node
            if temp.subtree.is_none() {
                return Err(StorageError::DomainNotFoundError(Some(clone.clone())));
            }
            let result = temp
                .subtree
                .as_mut()
                .unwrap()
                .get(&label.clone())
                .cloned();
            /// subtree exist and has label node
            if let Some(node) = result {
                if labels_count == 0 {
                    return Ok(node);
                }
                current = node;
                continue;
            }
            /// find if include wildcard *
            let result = temp
                .subtree
                .as_mut()
                .unwrap()

                .get(&WILDCARD_LABEL)
                .cloned();
            if let Some(node) = result {
                return Ok(node);
            }
            /// not found in subtree
            return Err(StorageError::DomainNotFoundError(Some(clone.clone())));
        }
        Ok(current)
    }

    // pub fn insert(&mut self, rr: ResourceRecord) -> Result<(), StorageError> {
    //     /// TODO: DO i need to check if the rr is below to this zone?
    //     let node = self.find_or_insert(rr.get_dname());
    //     node.borrow_mut().add_rr(rr)
    // }
}

impl RBTreeNode {
    fn has_type(&self, qtype: DNSType) -> bool {
        for (q_type, _) in self.rr_sets.iter() {
            if *q_type == qtype {
                return true;
            }
        }
        false
    }
    fn has_non_type(&self, qtype: DNSType) -> bool {
        for (q_type, _) in self.rr_sets.iter() {
            if *q_type != qtype {
                return true;
            }
        }
        false
    }
    pub fn find_rrset(&mut self, dtype: DNSType) -> Result<&RRSet, StorageError> {
        match self.rr_sets.get(&dtype) {
            Some(rrset) => Ok(rrset),
            None => Err(StorageError::DNSTypeNotFoundError),
        }
    }

    pub fn delete_rrset(&mut self, dtype: DNSType) -> Result<RRSet, StorageError> {
        match self.rr_sets.remove(&dtype) {
            Some(rrset) => Ok(rrset),
            None => Err(StorageError::DNSTypeNotFoundError),
        }
    }

    pub fn add_rr(&mut self, rr: ResourceRecord) -> Result<(), StorageError> {
        match rr.get_type() {
            DNSType::RRSIG => {
                self.rr_sets
                    .entry(rr.get_type())
                    .or_insert_with(Default::default)
                    .add(rr);
            }
            DNSType::CNAME => {
                if self.has_non_type(DNSType::NSEC) {
                    return Err(StorageError::AddCNAMEConflictError);
                }
            }
            _ => {
                if self.has_type(DNSType::CNAME) && rr.get_type() != DNSType::NSEC {
                    return Err(StorageError::AddOtherRRConflictCNAME);
                }
                self.rr_sets
                    .entry(rr.get_type())
                    .or_insert_with(Default::default)
                    .add(rr);
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
        let mut current = self.parent.borrow().upgrade();
        while let Some(mut value) = current {
            let label = (*value).borrow_mut().label.to_owned();
            if label.is_empty() {
                break;
            }
            labels.push(label);
            current = (*value).borrow_mut().parent.borrow().upgrade();
        }
        DNSName { labels }
    }
    /// create a new node from dns label and with default values.
    fn from_label(label: Label) -> Rc<RefCell<RBTreeNode>> {
        Rc::new(RefCell::new(RBTreeNode {
            label,
            rr_sets: Default::default(),
            parent: RefCell::new(Weak::new()),
            subtree: None,
        }))
    }
}

#[cfg(test)]
mod storage {
    use super::*;
    use dnsproto::meta::DNSClass;
    use std::str::FromStr;

    fn example_zone() -> RBZone {
        let zone: RBZone = RBZone::new_root();
        let dnsnames = vec![
            (
                DNSName::new("baidu.com").unwrap(),
                ResourceRecord::new("baidu.com.", DNSType::A, DNSClass::IN, 1000, None).unwrap(),
            ),
            (
                DNSName::new("www.google.com.").unwrap(),
                ResourceRecord::new("www.google.com.", DNSType::A, DNSClass::IN, 1000, None)
                    .unwrap(),
            ),
            (
                DNSName::new("google.com.").unwrap(),
                ResourceRecord::new("google.com.", DNSType::NS, DNSClass::IN, 1000, None).unwrap(),
            ),
            (
                DNSName::new("*.baidu.com").unwrap(),
                ResourceRecord::new("*.baidu.com.", DNSType::A, DNSClass::IN, 1234, None).unwrap(),
            ),
            (
                DNSName::new("test\\.dns.baidu.com").unwrap(),
                ResourceRecord::new(
                    "test\\.dns.baidu.com.",
                    DNSType::A,
                    DNSClass::IN,
                    1234,
                    None,
                )
                .unwrap(),
            ),
            (
                DNSName::new("www.google.com.").unwrap(),
                ResourceRecord::new("www.google.com.", DNSType::NS, DNSClass::IN, 1000, None)
                    .unwrap(),
            ),
        ];
        for (name, rr) in dnsnames {
            let mut node = zone.find_or_insert(&name);
            let mut borrow_node = node.deref().borrow_mut();
            if let Err(_e) = borrow_node.add_rr(rr) {
                panic!("create example zone fail");
            }
        }
        zone
    }
    #[test]
    fn test_rb_node() {
        let parent_node = Rc::new(RefCell::new(RBTreeNode {
            label: Label::from_str("com").unwrap(),
            rr_sets: Default::default(),
            parent: RefCell::new(Weak::new()),
            subtree: None,
        }));
        let mut node = Rc::new(RefCell::new(RBTreeNode {
            label: Label::from_str("baidu").unwrap(),
            rr_sets: Default::default(),
            parent: RefCell::new(Weak::new()),
            subtree: None,
        }));
        *node.deref().borrow_mut().parent.borrow_mut() = Rc::downgrade(&parent_node);
        let child = RBTreeNode {
            label: Label::from_str("www").unwrap(),
            rr_sets: Default::default(),
            parent: RefCell::new(Weak::new()),
            subtree: None,
        };
        *child.parent.borrow_mut() = Rc::downgrade(&node);
        assert_eq!(child.get_name().to_string(), "www.baidu.com.".to_owned());
        let node = RBTreeNode {
            label: Label::root(),
            rr_sets: Default::default(),
            parent: RefCell::new(Weak::new()),
            subtree: None,
        };
        assert_eq!(node.get_name().to_string(), ".".to_owned());
    }
    #[test]
    fn test_find_or_insert() {
        let zone = RBZone::new_root();
        let mut node = zone.find_or_insert(&DNSName::new("www.baidu.com").unwrap());
        assert_eq!(node.deref().borrow_mut().label, Label::from_str("www").unwrap());
        assert_eq!(
            node.deref().borrow_mut().get_name(),
            DNSName::new("www.baidu.com").unwrap()
        );
    }

    #[test]
    fn test_rb_storage_insert() {
        let zone = example_zone();
        let dname = DNSName::new("baidu.com").unwrap();
        match zone.find(&dname) {
            Ok(mut node) => assert_eq!(node.deref().borrow_mut().rr_sets.len(), 1),
            _ => assert!(false),
        }

        let dname = DNSName::new("ftp.baidu.com").unwrap();
        match zone.find(&dname) {
            // find wirdcard match
            Ok(mut node) => {
                assert_eq!(node.deref().borrow_mut().rr_sets.len(), 1);
                assert_eq!(node.deref().borrow_mut().rr_sets.get(&DNSType::A).is_some(), true);
            }
            _ => assert!(false),
        }
    }

    #[test]
    fn test_node_rr_method() {
        let mut node = RBTreeNode {
            label: Label::from_str("com").unwrap(),
            rr_sets: HashMap::new(),
            parent: RefCell::new(Weak::new()),
            subtree: None,
        };
        let rr = ResourceRecord::new("google.com.", DNSType::NS, DNSClass::IN, 1000, None).unwrap();
        if let Err(_) = node.add_rr(rr) {
            assert!(false)
        }
        let rr = ResourceRecord::new("*", DNSType::A, DNSClass::IN, 1000, None).unwrap();
        if let Err(_) = node.add_rr(rr) {
            assert!(false)
        }
        let rr =
            ResourceRecord::new("google.com.", DNSType::SOA, DNSClass::IN, 1000, None).unwrap();
        if let Err(_) = node.add_rr(rr) {
            assert!(false)
        }
        let rr =
            ResourceRecord::new("google.com.", DNSType::CNAME, DNSClass::IN, 1000, None).unwrap();
        if let Err(_) = node.add_rr(rr) {
            assert!(true)
        }
        let rr = ResourceRecord::new(
            "abc\\.google.com.",
            DNSType::CNAME,
            DNSClass::IN,
            1000,
            None,
        )
        .unwrap();
        if let Err(_) = node.add_rr(rr) {
            assert!(true)
        }
    }
}
