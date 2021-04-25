use crate::unsafe_rbtree::{RBTreeNode, UnSafeRBTreeStorage};
use dashmap::DashMap;
use dnsproto::dnsname::DNSName;
use dnsproto::label::Label;
use dnsproto::meta::DNSType::A;
use dnsproto::meta::{DNSType, RRSet, ResourceRecord};
use dnsproto::zone::{ZoneFileParser, ZoneReader};
use lazy_static::lazy_static;
use otterlib::errors::{OtterError, StorageError};
use std::cell::RefCell;
use std::collections::btree_map::Iter;
use std::collections::BTreeMap;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use std::sync::{Arc, Mutex, RwLock, Weak};

lazy_static! {
    static ref WILDCARD_LABEL: Label = Label::from_str("*").unwrap();
}

#[derive(Debug)]
pub struct SafeRBTreeNode {
    label: Label,
    pub(crate) rr_sets: DashMap<DNSType, Arc<RwLock<RRSet>>>,
    parent: Option<Weak<RwLock<SafeRBTreeNode>>>,
    subtree: Arc<RwLock<BTreeMap<Label, Arc<RwLock<SafeRBTreeNode>>>>>,
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
        loop {
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
                        Some(next.clone())
                    };

                    // no more item in this tree shift to another sub tree
                    self.next = Some(parent.clone());
                }
                Some(next)
            } else {
                None
            };
        }
    }
}

// //
// impl Iterator for SafeZoneIterator {
//     type Item = Arc<RwLock<RBTreeNode>>;
//     fn next(&mut self) -> Option<Self::Item> {
//         loop {
//             if let Some(next) = self.next.take() {
//                     if let Some(parent) = self.parent_stack.pop() {
//                         if let Some(tree) = &parent.read().unwrap().subtree {
//                             if let Some(v) = tree.read().unwrap() {
//                                 self.next = Some((v.0.clone(), Some(v.1)));
//                                 self.parent_stack.push((parent.0.clone(), parent.1));
//                                 return Some(next);
//                             }
//                             // no more item in this tree shift to another sub tree
//                             self.next = Some((parent.0.clone(), parent.1));
//                             return Some(next);
//                         }
//                     }
//                 } else {
//                     return Some(next);
//                 }
//             } else {
//                 return None;
//             }
//         }
//     }
// }

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
    pub fn add_rr(&mut self, rr: ResourceRecord) -> Result<(), StorageError> {
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
    fn from_label(label: Label) -> Arc<RwLock<SafeRBTreeNode>> {
        Arc::new(RwLock::new(SafeRBTreeNode {
            label,
            rr_sets: Default::default(),
            parent: None,
            subtree: Arc::new(RwLock::new(BTreeMap::new())),
        }))
    }
}

#[derive(Debug, Clone)]
pub struct SafeRBTreeStorage(Arc<RwLock<SafeRBTreeNode>>);

unsafe impl Send for SafeRBTreeStorage {}

impl Default for SafeRBTreeStorage {
    fn default() -> Self {
        SafeRBTreeStorage::new(SafeRBTreeNode::new_root())
    }
}

impl SafeRBTreeStorage {
    pub fn new(node: SafeRBTreeNode) -> SafeRBTreeStorage {
        SafeRBTreeStorage(Arc::new(RwLock::new(node)))
    }

    pub fn new_zone_from_file(
        file: &str,
        default_origin: Option<String>,
    ) -> Result<SafeRBTreeStorage, OtterError> {
        let mut zone = SafeRBTreeStorage::new(SafeRBTreeNode::new_root());
        zone.update_zone(file, default_origin)?;
        Ok(zone)
    }

    pub fn update_zone(
        &mut self,
        file: &str,
        default_origin: Option<String>,
    ) -> Result<(), OtterError> {
        let parser = ZoneFileParser::new(file)?;
        let zone_reader = ZoneReader::new(parser, default_origin);
        for item in zone_reader {
            match item {
                Ok(rr) => {
                    // insert rr record to zone node.
                    self.insert_rr(rr)?;
                }
                Err(err) => return Err(OtterError::DNSProtoError(err)),
            }
        }
        Ok(())
    }

    /// locate the dns name node from top zone root node. if the dns name is not found in this zone
    /// create a sub node based the label.
    /// should valid if the name is below to the zone data.
    pub fn find_or_insert(
        &mut self,
        name: &DNSName,
    ) -> Result<Arc<RwLock<SafeRBTreeNode>>, StorageError> {
        let current_name = &self.0.read().unwrap().get_name();
        if !name.is_part_of(current_name) {
            return Err(StorageError::ZoneOutOfArea(
                name.to_string(),
                current_name.to_string(),
            ));
        }
        let mut labels_count = name.label_count();
        if labels_count == 0 {
            return Ok(self.0.clone());
        }
        let mut parent_node = None;
        let mut current = self.0.clone();

        for label in name.labels.iter().rev() {
            labels_count -= 1;

            let result = current
                .read()
                .unwrap()
                .subtree
                .read()
                .unwrap()
                .get(&label.clone())
                .cloned();

            if let Some(node) = result {
                if labels_count == 0 {
                    return Ok(node);
                }
                parent_node = Some(node.clone());
                current = node;
                continue;
            }

            let node = SafeRBTreeNode::from_label(label.clone());
            if let Some(parent) = parent_node {
                (*node).write().unwrap().parent = Some(Arc::downgrade(&parent));
            } else {
                (*node).write().unwrap().parent = None
            }
            current
                .read()
                .unwrap()
                .subtree
                .write()
                .unwrap()
                .insert(label.clone(), node.clone());
            // not found in subtree
            if labels_count == 0 {
                // subtree exist but has not label node
                // create a new label node
                return Ok(node);
            } else {
                // create a path to next label, but if each label has a new rbtree will consume
                // too much memory , so should build with a compressed way
                current = node.clone();
                parent_node = Some(node);
            }
        }
        Ok(current)
    }

    pub fn insert_rr(&mut self, rr: ResourceRecord) -> Result<(), StorageError> {
        let dname = rr.get_dname();
        let vnode = self.find_or_insert(dname)?;
        vnode.write().unwrap().add_rr(rr)?;
        Ok(())
    }
    /// search will travel from top of tree down to the bottom.
    pub fn search_rrset(
        &mut self,
        dname: &DNSName,
        dtype: &DNSType,
    ) -> Result<Arc<RwLock<RRSet>>, StorageError> {
        let node = self.find(dname)?;
        let node = node.read().unwrap();
        let result = match node.rr_sets.get(dtype) {
            Some(rrset) => Ok(rrset.clone()),
            None => Err(StorageError::DNSTypeNotFoundError(
                dname.to_string(),
                dtype.to_string(),
            )),
        };
        result
    }

    pub fn delete_rrset(&mut self, dtype: DNSType) -> Result<(), StorageError> {
        let name = self.0.read().unwrap().get_name();
        match self.0.write().unwrap().rr_sets.remove(&dtype) {
            Some(_) => Ok(()),
            None => Err(StorageError::DNSTypeNotFoundError(
                name.to_string(),
                dtype.to_string(),
            )),
        }
    }

    pub fn find_best(&self, name: &DNSName) -> Arc<RwLock<SafeRBTreeNode>> {
        let mut labels_count = name.label_count();
        if labels_count == 0 {
            return self.0.clone();
        }
        let mut current = self.0.clone();
        for label in name.labels.iter().rev() {
            labels_count -= 1;
            let temp = current.clone();
            let subtree = temp.read().unwrap().subtree.clone();
            let subtree = subtree.read().unwrap();
            let result = subtree.get(&label.clone());
            /// subtree exist and has label node
            if let Some(node) = result {
                if labels_count == 0 {
                    return node.clone();
                }
                current = node.clone();
                continue;
            }
            return current;
        }
        current
    }
    pub fn find_smallest(
        &self,
        stack: &mut Vec<Arc<RwLock<SafeRBTreeNode>>>,
    ) -> Arc<RwLock<SafeRBTreeNode>> {
        let current = self.0.clone();
        let subtree = current.read().unwrap().subtree.clone();
        if let Some((_, val)) = subtree.read().unwrap().iter().next() {
            stack.push(current.clone());
            let subtree = SafeRBTreeStorage(val.clone());
            return subtree.find_smallest(stack);
        }
        current
    }
    pub fn get_additionals(&mut self, names: Vec<&DNSName>) -> Vec<Arc<RwLock<RRSet>>> {
        // TODO: if name is not in current zone , do we need to return the glue records, maybe ignore it.
        let mut results = vec![];
        for name in names.iter() {
            if self.is_relative(name) == false {
                continue;
            }
            if let Ok(result) = self.find(name) {
                let node = result.read().unwrap();
                if let Some(result) = node.rr_sets.get(&DNSType::A) {
                    results.push(result.value().clone());
                }
                if let Some(result) = node.rr_sets.get(&DNSType::AAAA) {
                    results.push(result.value().clone());
                }
            }
        }
        results
    }

    pub fn is_relative(&self, name: &DNSName) -> bool {
        let zone = self.0.read().unwrap().get_name();
        let (is_relative, _) = name.is_relative(&zone);
        is_relative
    }

    pub fn find(&mut self, name: &DNSName) -> Result<Arc<RwLock<SafeRBTreeNode>>, StorageError> {
        let mut labels_count = name.label_count();
        if labels_count == 0 {
            return Ok(self.0.clone());
        }
        let mut current = self.0.clone();
        for label in name.labels.iter().rev() {
            labels_count -= 1;
            let temp = current.clone();
            let subtree = temp.read().unwrap().subtree.clone();
            /// subtree exist and has label node
            if let Some(node) = subtree.read().unwrap().get(&label.clone()) {
                if labels_count == 0 {
                    return Ok(node.clone());
                }
                current = node.clone();
                continue;
            }
            if let Some(node) = subtree.read().unwrap().get(&WILDCARD_LABEL) {
                return Ok(node.clone());
            }
            /// not found in subtree
            return Err(StorageError::DomainNotFoundError(name.to_string()));
        }
        Ok(current)
    }
}
