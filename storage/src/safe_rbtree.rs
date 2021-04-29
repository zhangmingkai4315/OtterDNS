use crate::storage::SafeRBTreeStorage;
use dashmap::DashMap;
use dnsproto::dnsname::DNSName;
use dnsproto::label::Label;
use dnsproto::meta::{DNSType, RRSet, ResourceRecord};

use otterlib::errors::StorageError;
use std::collections::BTreeMap;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::sync::{Arc, RwLock, Weak};

#[derive(Debug)]
pub struct SafeRBTreeNode {
    label: Label,
    pub(crate) auth_data: bool,
    pub(crate) rr_sets: DashMap<DNSType, Arc<RwLock<RRSet>>>,
    pub(crate) parent: Option<Weak<RwLock<SafeRBTreeNode>>>,
    pub(crate) subtree: Arc<RwLock<BTreeMap<Label, Arc<RwLock<SafeRBTreeNode>>>>>,
}

pub struct SafeZoneIterator {
    parent_stack: Vec<Arc<RwLock<SafeRBTreeNode>>>,
    next: Option<Arc<RwLock<SafeRBTreeNode>>>,
}

impl IntoIterator for SafeRBTreeStorage {
    type Item = Arc<RwLock<SafeRBTreeNode>>;
    type IntoIter = SafeZoneIterator;

    fn into_iter(self) -> Self::IntoIter {
        let mut stack = Vec::new();
        let smallest = self.find_smallest(&mut stack);
        SafeZoneIterator {
            parent_stack: stack,
            next: Some(smallest),
        }
    }
}

impl Iterator for SafeZoneIterator {
    type Item = Arc<RwLock<SafeRBTreeNode>>;
    fn next(&mut self) -> Option<Self::Item> {
        return if let Some(next) = self.next.take() {
            if let Some(parent) = self.parent_stack.pop() {
                let tree = &parent.read().unwrap().subtree;

                return if let Some(v) = tree
                    .read()
                    .unwrap()
                    .range(&next.read().unwrap().label..)
                    .next()
                {
                    self.next = Some(v.1.clone());
                    self.parent_stack.push(parent.clone());
                    Some(next.clone())
                } else {
                    self.next = Some(parent.clone());
                    Some(next.clone())
                };

                // no more item in this tree shift to another sub tree
            }
            Some(next)
        } else {
            None
        };
    }
}

impl Display for SafeRBTreeNode {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        for rrset in self.rr_sets.iter() {
            let _ = write!(formatter, "{}", rrset.read().unwrap().to_string());
        }
        write!(formatter, "")
    }
}

// type DNSTreeStorage = Rc<RefCell<RBTreeNode>>;

impl SafeRBTreeNode {
    pub fn new_root() -> SafeRBTreeNode {
        SafeRBTreeNode {
            label: Label::root(),
            auth_data: false,
            rr_sets: Default::default(),
            parent: None,
            subtree: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }
    pub fn find_soa(&self) -> Result<Arc<RwLock<RRSet>>, StorageError> {
        return match self.find_rrset(DNSType::SOA) {
            Ok(rrset) => Ok(rrset),
            _ => {
                if let Some(parent) = &self.parent {
                    if let Some(parent) = parent.upgrade() {
                        return parent.read().unwrap().find_soa();
                    }
                }
                Err(StorageError::SOAResourceError)
            }
        };
    }

    fn is_empty(&self) -> bool {
        self.subtree.read().unwrap().is_empty()
    }
    pub fn add_rr(&mut self, rr: ResourceRecord) -> Result<(), StorageError> {
        self.auth_data = true;
        match rr.get_type() {
            DNSType::RRSIG => {
                self.rr_sets
                    .entry(rr.get_type())
                    .or_insert_with(Default::default)
                    .value()
                    .write()
                    .unwrap()
                    .add(rr);
            }
            DNSType::CNAME => {
                if self.has_non_type(&DNSType::NSEC) {
                    return Err(StorageError::AddCNAMEConflictError);
                } else {
                    self.rr_sets
                        .entry(rr.get_type())
                        .or_insert_with(Default::default)
                        .value()
                        .write()
                        .unwrap()
                        .add(rr);
                }
            }
            _ => {
                if self.has_type(&DNSType::CNAME) && rr.get_type() != DNSType::NSEC {
                    return Err(StorageError::AddOtherRRConflictCNAME);
                }
                self.rr_sets
                    .entry(rr.get_type())
                    .or_insert_with(Default::default)
                    .value()
                    .write()
                    .unwrap()
                    .add(rr);
            }
        }
        Ok(())
    }
    fn has_type(&self, qtype: &DNSType) -> bool {
        for v in self.rr_sets.iter() {
            if v.key() == qtype {
                return true;
            }
        }
        false
    }
    fn has_non_type(&self, qtype: &DNSType) -> bool {
        for v in self.rr_sets.iter() {
            if v.key() != qtype {
                return true;
            }
        }
        false
    }
    pub fn find_rrset(&self, dtype: DNSType) -> Result<Arc<RwLock<RRSet>>, StorageError> {
        match self.rr_sets.get(&dtype) {
            Some(rrset) => Ok(rrset.clone()),
            None => Err(StorageError::DNSTypeNotFoundError(
                self.get_name().to_string(),
                dtype.to_string(),
            )),
        }
    }

    #[allow(dead_code)]
    fn get_parent(&self) -> Option<Arc<RwLock<SafeRBTreeNode>>> {
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
                let label = (*value).read().unwrap().label.to_owned();
                if label.is_empty() {
                    break;
                }
                labels.push(label);
                if let Some(parent) = &(*value).read().unwrap().parent {
                    current = parent.upgrade();
                } else {
                    break;
                }
            }
        }
        DNSName { labels }
    }
    /// create a new node from dns label and with default values.
    pub(crate) fn from_label(label: Label) -> Arc<RwLock<SafeRBTreeNode>> {
        Arc::new(RwLock::new(SafeRBTreeNode {
            label,
            auth_data: false,
            rr_sets: Default::default(),
            parent: None,
            subtree: Arc::new(RwLock::new(BTreeMap::new())),
        }))
    }
}
