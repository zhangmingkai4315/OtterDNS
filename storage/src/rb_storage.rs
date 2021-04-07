// a red-black-tree storage for store all dns data
// use intrusive_collections::{RBTree, intrusive_adapter, RBTreeLink, KeyAdapter};
// use std::cell::Cell;
use crate::rbtree::RBTree;
// use crate::Storage;
use dnsproto::dnsname::DNSName;
use dnsproto::label::Label;
use dnsproto::meta::{DNSType, RRSet, ResourceRecord};
use lazy_static::lazy_static;
use otterlib::errors::StorageError;
use std::cell::RefCell;
use std::collections::HashMap;
use std::ops::Deref;
use std::rc::{Rc, Weak};
use std::str::FromStr;
// use std::borrow::{Borrow, BorrowMut};
// use std::iter::IntoIterator;
// use std::vec::IntoIter;

lazy_static! {
    static ref WILDCARD_LABEL: Label = Label::from_str("*").unwrap();
}

#[derive(Debug)]
pub struct RBTreeNode {
    label: Label,
    rr_sets: HashMap<DNSType, RRSet>,
    parent: Option<Weak<RefCell<RBTreeNode>>>,
    subtree: Option<RBTree<Label, Rc<RefCell<RBTreeNode>>>>,
}

pub struct ZoneIterator {
    parent_stack: Vec<(Rc<RefCell<RBTreeNode>>, Option<usize>)>,
    next: Option<(Rc<RefCell<RBTreeNode>>, Option<usize>)>,
}

impl IntoIterator for RBTreeNode {
    type Item = Rc<RefCell<RBTreeNode>>;
    type IntoIter = ZoneIterator;

    fn into_iter(self) -> Self::IntoIter {
        let mut stack = Vec::new();
        let (smallest, id) =
            RBTreeNode::find_smallest(Rc::new(RefCell::new(self)), &mut stack, None);
        ZoneIterator {
            parent_stack: stack,
            next: Some((smallest, id)),
        }
    }
}

impl Iterator for ZoneIterator {
    type Item = Rc<RefCell<RBTreeNode>>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some((next, id)) = self.next.take() {
                if let Some(id) = id {
                    if let Some(parent) = self.parent_stack.pop() {
                        if let Some(tree) = &parent.0.deref().borrow().subtree {
                            if let Some(v) = tree.find_next_value(id) {
                                self.next = Some((v.0.clone(), Some(v.1)));
                                self.parent_stack.push((parent.0.clone(), parent.1));
                                return Some(next);
                            }
                            // no more item in this tree shift to another sub tree
                            self.next = Some((parent.0.clone(), parent.1));
                            return Some(next);
                        }
                    }
                } else {
                    return Some(next);
                }
            } else {
                return None;
            }
        }
    }
}

impl RBTreeNode {
    pub fn new_root() -> RBTreeNode {
        RBTreeNode {
            label: Label::root(),
            rr_sets: Default::default(),
            parent: None,
            subtree: None,
        }
    }

    pub fn find_smallest(
        current: Rc<RefCell<RBTreeNode>>,
        stack: &mut Vec<(Rc<RefCell<RBTreeNode>>, Option<usize>)>,
        id: Option<usize>,
    ) -> (Rc<RefCell<RBTreeNode>>, Option<usize>) {
        if let Some(subtree) = &current.deref().borrow_mut().subtree {
            if let Some((val, id)) = subtree.find_smallest_value() {
                stack.push((current.clone(), Some(id)));
                return RBTreeNode::find_smallest(val.clone(), stack, Some(id));
            }
        }
        (current, id)
    }
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
    pub fn find_rrset(&self, dtype: DNSType) -> Result<&RRSet, StorageError> {
        match self.rr_sets.get(&dtype) {
            Some(rrset) => Ok(rrset),
            None => Err(StorageError::DNSTypeNotFoundError),
        }
    }

    pub fn insert_rr(&mut self, rr: ResourceRecord) -> Result<(), StorageError> {
        let dname = rr.get_dname();
        let vnode = self.find_or_insert(dname)?;
        vnode.add_rr(rr)?;
        Ok(())
    }

    pub fn delete_rrset(&mut self, dtype: DNSType) -> Result<RRSet, StorageError> {
        match self.rr_sets.remove(&dtype) {
            Some(rrset) => Ok(rrset),
            None => Err(StorageError::DNSTypeNotFoundError),
        }
    }

    /// locate the dns name node from top zone root node. if the dns name is not found in this zone
    /// create a sub node based the label.
    /// should valid if the name is below to the zone data.
    pub fn find_or_insert(&mut self, name: &DNSName) -> Result<&mut RBTreeNode, StorageError> {
        if !name.is_part_of(&self.get_name()) {
            return Err(StorageError::ZoneOutOfArea(
                name.to_string(),
                self.get_name().to_string(),
            ));
        }
        let mut labels_count = name.label_count();
        if labels_count == 0 {
            return Ok(self);
        }
        let mut parent_node = None;
        let mut current = self;

        for label in name.labels.iter().rev() {
            labels_count -= 1;
            let subtree = current.subtree.get_or_insert(RBTree::new());
            let result = subtree.get(&label.clone()).cloned();
            /// subtree exist and has label node
            if let Some(node) = result {
                if labels_count == 0 {
                    return Ok(unsafe { node.as_ptr().as_mut().unwrap() });
                }
                parent_node = Some(node.clone());
                current = unsafe { node.as_ptr().as_mut().unwrap() };
                continue;
            }
            let node = RBTreeNode::from_label(label.clone());
            if let Some(parent) = parent_node {
                (*node).borrow_mut().parent = Some(Rc::downgrade(&parent));
            } else {
                (*node).borrow_mut().parent = None
            }
            subtree.insert(label.clone(), node.clone());
            // not found in subtree
            if labels_count == 0 {
                // subtree exist but has not label node
                // create a new label node
                return Ok(unsafe { node.as_ptr().as_mut().unwrap() });
            } else {
                // create a path to next label, but if each label has a new rbtree will consume
                // too much memory , so should build with a compressed way
                current = unsafe { node.clone().as_ptr().as_mut().unwrap() };
                parent_node = Some(node);
            }
        }
        Ok(current)
    }
    pub fn find_best(&self, name: &DNSName) -> &RBTreeNode {
        let mut labels_count = name.label_count();
        if labels_count == 0 {
            return self;
        }
        let mut current = self;
        for label in name.labels.iter().rev() {
            labels_count -= 1;
            if current.subtree.is_none() {
                return self;
            }
            let result = current
                .subtree
                .as_ref()
                .unwrap()
                .get(&label.clone())
                .cloned();
            /// subtree exist and has label node
            if let Some(node) = result {
                if labels_count == 0 {
                    return unsafe { node.as_ptr().as_ref().unwrap() };
                }
                current = unsafe { node.as_ptr().as_ref().unwrap() };
                continue;
            }
            return current;
        }
        current
    }
    pub fn find(&self, name: &DNSName) -> Result<&RBTreeNode, StorageError> {
        let mut labels_count = name.label_count();
        if labels_count == 0 {
            return Ok(self);
        }
        let mut current = self;
        for label in name.labels.iter().rev() {
            labels_count -= 1;
            if current.subtree.is_none() {
                return Err(StorageError::DomainNotFoundError(name.to_string()));
            }
            let result = current
                .subtree
                .as_ref()
                .unwrap()
                .get(&label.clone())
                .cloned();
            /// subtree exist and has label node
            if let Some(node) = result {
                if labels_count == 0 {
                    return Ok(unsafe { node.as_ptr().as_ref().unwrap() });
                }
                current = unsafe { node.as_ptr().as_ref().unwrap() };
                continue;
            }
            /// find if include wildcard *
            let result = current
                .subtree
                .as_ref()
                .unwrap()
                .get(&WILDCARD_LABEL)
                .cloned();
            if let Some(node) = result {
                return Ok(unsafe { node.as_ptr().as_ref().unwrap() });
            }
            /// not found in subtree
            return Err(StorageError::DomainNotFoundError(name.to_string()));
        }
        Ok(current)
    }
    pub fn find_soa(&self) -> Result<&ResourceRecord, StorageError> {
        return match self.find_rrset(DNSType::SOA) {
            Ok(rrset) => {
                if rrset.content().len() != 1 {
                    return Err(StorageError::SOAResourceError);
                }
                Ok(rrset.content().get(0).unwrap())
            }
            _ => {
                if let Some(parent) = &self.parent {
                    if let Some(parent) = parent.upgrade() {
                        match unsafe { parent.as_ptr().as_ref() } {
                            Some(parent) => {
                                return parent.find_soa();
                            }
                            _ => return Err(StorageError::SOAResourceError),
                        };
                    }
                }
                Err(StorageError::SOAResourceError)
            }
        };
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
    fn get_parent(&self) -> Option<Rc<RefCell<RBTreeNode>>> {
        if let Some(parent) = self.parent.clone() {
            parent.upgrade()
        } else {
            None
        }
    }

    #[allow(dead_code)]
    pub fn get_name(&self) -> DNSName {
        if self.label.is_empty() {
            return DNSName { labels: vec![] };
        }
        let mut labels = vec![];
        labels.push(self.label.clone());
        if let Some(parent) = &self.parent {
            let mut current = parent.upgrade();
            while let Some(value) = current {
                let label = (*value).borrow_mut().label.to_owned();
                if label.is_empty() {
                    break;
                }
                labels.push(label);
                if let Some(parent) = &(*value).borrow_mut().parent {
                    current = parent.upgrade();
                } else {
                    break;
                }
            }
        }
        DNSName { labels }
    }
    /// create a new node from dns label and with default values.
    fn from_label(label: Label) -> Rc<RefCell<RBTreeNode>> {
        Rc::new(RefCell::new(RBTreeNode {
            label,
            rr_sets: Default::default(),
            parent: None,
            subtree: None,
        }))
    }
}

#[cfg(test)]
mod storage {
    use super::*;
    use dnsproto::meta::DNSClass;
    use dnsproto::qtype::DnsTypeSOA;
    use std::str::FromStr;

    fn example_zone_v2() -> RBTreeNode {
        let mut zone: RBTreeNode = RBTreeNode::new_root();
        zone.add_rr(
            ResourceRecord::new(
                ".",
                DNSType::SOA,
                DNSClass::IN,
                1000,
                Some(Box::new(
                    DnsTypeSOA::new(
                        "a.root-servers.net.",
                        "nstld.verisign-grs.com.",
                        2021033102,
                        1800,
                        900,
                        604800,
                        86400,
                    )
                    .unwrap(),
                )),
            )
            .unwrap(),
        )
        .unwrap();
        let dnsnames = vec![
            (
                DNSName::new("baidu.com").unwrap(),
                ResourceRecord::new("baidu.com.", DNSType::A, DNSClass::IN, 1000, None).unwrap(),
            ),
            (
                DNSName::new("baidu.com").unwrap(),
                ResourceRecord::new(
                    "baidu.com.",
                    DNSType::SOA,
                    DNSClass::IN,
                    1000,
                    Some(Box::new(
                        DnsTypeSOA::new(
                            "dns.baidu.com.",
                            "sa.baidu.com",
                            2012144258,
                            300,
                            300,
                            2592000,
                            7200,
                        )
                        .unwrap(),
                    )),
                )
                .unwrap(),
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
            let node = zone.find_or_insert(&name).unwrap();
            // let mut borrow_node = node.deref().borrow_mut();
            if let Err(_e) = node.add_rr(rr) {
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
            parent: None,
            subtree: None,
        }));
        let node = Rc::new(RefCell::new(RBTreeNode {
            label: Label::from_str("baidu").unwrap(),
            rr_sets: Default::default(),
            parent: None,
            subtree: None,
        }));
        node.deref().borrow_mut().parent = Some(Rc::downgrade(&parent_node));
        let mut child = RBTreeNode {
            label: Label::from_str("www").unwrap(),
            rr_sets: Default::default(),
            parent: None,
            subtree: None,
        };
        child.parent = Some(Rc::downgrade(&node));
        assert_eq!(child.get_name().to_string(), "www.baidu.com.".to_owned());
        let node = RBTreeNode {
            label: Label::root(),
            rr_sets: Default::default(),
            parent: None,
            subtree: None,
        };
        assert_eq!(node.get_name().to_string(), ".".to_owned());
    }
    #[test]
    fn test_find_or_insert() {
        let mut zone = RBTreeNode::new_root();
        let node = zone
            .find_or_insert(&DNSName::new("www.baidu.com").unwrap())
            .unwrap();
        assert_eq!(node.label, Label::from_str("www").unwrap());
        assert_eq!(node.get_name(), DNSName::new("www.baidu.com").unwrap());

        let insert_out_of_zone = node.find_or_insert(&DNSName::new("www.google.cc").unwrap());
        assert_eq!(
            insert_out_of_zone.unwrap_err(),
            StorageError::ZoneOutOfArea("www.google.cc.".to_owned(), "www.baidu.com.".to_owned())
        )
    }

    #[test]
    fn test_node_rr_method() {
        let mut node = RBTreeNode {
            label: Label::from_str("com").unwrap(),
            rr_sets: HashMap::new(),
            parent: None,
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

    #[test]
    fn test_rbnode_insert() {
        let zone = example_zone_v2();
        let dname = DNSName::new("baidu.com").unwrap();
        match zone.find(&dname) {
            Ok(node) => assert_eq!(node.rr_sets.len(), 2),
            _ => assert!(false),
        }

        let dname = DNSName::new("ftp.baidu.com").unwrap();
        match zone.find(&dname) {
            // find wirdcard match
            Ok(node) => {
                assert_eq!(node.rr_sets.len(), 1);
                assert_eq!(node.rr_sets.get(&DNSType::A).is_some(), true);
            }
            _ => assert!(false),
        }
    }

    #[test]
    fn test_find_smallest() {
        let zone = example_zone_v2();
        let zone_rc = Rc::new(RefCell::new(zone));
        let mut stack = vec![];
        let smallest = RBTreeNode::find_smallest(zone_rc, &mut stack, None);
        assert_eq!(
            smallest.0.deref().borrow().label,
            Label::from_str("*").unwrap()
        );
        assert_eq!(stack.len(), 3);
        let zone = RBTreeNode::new_root();
        let zone_rc = Rc::new(RefCell::new(zone));
        let mut stack = vec![];
        let smallest = RBTreeNode::find_smallest(zone_rc, &mut stack, None);
        assert_eq!(smallest.0.deref().borrow().label, Label::root());
        assert_eq!(stack.len(), 0);
    }

    #[test]
    fn test_rbtree_iterator() {
        let zone = example_zone_v2();
        let mut index = 0;
        let iter_order = [
            "*.baidu.com.",
            "test\\.dns.baidu.com.",
            "baidu.com.",
            "google.com.",
            "com.",
            ".",
        ];
        for ix in zone {
            assert_eq!(
                ix.deref().borrow().get_name().to_string(),
                String::from(iter_order[index])
            );
            index = index + 1;
        }

        let zone = RBTreeNode::new_root();
        for ix in zone {
            assert_eq!(
                ix.deref().borrow().get_name().to_string(),
                String::from(".")
            );
        }
    }
    #[test]
    fn test_find_best() {
        let zone = example_zone_v2();
        let best = zone.find_best(&DNSName::new("www.baidu.com").unwrap());
        assert_eq!(best.get_name().to_string(), "baidu.com.");
        let best = zone.find_best(&DNSName::new("www.google.com.").unwrap());
        assert_eq!(best.get_name().to_string(), "www.google.com.");

        let zone = RBTreeNode::new_root();
        let best = zone.find_best(&DNSName::new("www.baidu.com").unwrap());
        assert_eq!(best.get_name().to_string(), ".");
    }

    #[test]
    fn test_find_soa() {
        let zone = example_zone_v2();
        let soa = zone.find_soa().unwrap();
        let soa_record = DnsTypeSOA::new(
            "a.root-servers.net.",
            "nstld.verisign-grs.com.",
            2021033102,
            1800,
            900,
            604800,
            86400,
        )
        .unwrap();
        assert_eq!(soa.get_type(), DNSType::SOA);
        assert_eq!(soa.get_dname().to_string(), ".");
        assert_eq!(
            soa.get_data().as_ref().unwrap().to_string(),
            "a.root-servers.net. nstld.verisign-grs.com. ( 2021033102 1800 900 604800 86400 )"
        );
        assert_eq!(
            soa.get_data()
                .as_ref()
                .unwrap()
                .as_any()
                .downcast_ref::<DnsTypeSOA>(),
            Some(&soa_record)
        );
    }
}
