use crate::safe_rbtree::SafeRBTreeNode;
use dashmap::DashMap;
use dnsproto::dnsname::DNSName;
use dnsproto::label::Label;
use dnsproto::meta::{DNSType, RRSet, ResourceRecord};
use dnsproto::zone::{ZoneFileParser, ZoneReader};
use lazy_static::lazy_static;
use otterlib::errors::{OtterError, StorageError};
use std::str::FromStr;
use std::sync::{Arc, RwLock};
lazy_static! {
    static ref WILDCARD_LABEL: Label = Label::from_str("*").unwrap();
}

#[derive(Debug, Clone)]
pub struct SafeRBTreeStorage {
    domain_tree: Arc<RwLock<SafeRBTreeNode>>,
    fast_cache: DashMap<DNSName, Arc<RwLock<SafeRBTreeNode>>>,
}

unsafe impl Send for SafeRBTreeStorage {}

impl Default for SafeRBTreeStorage {
    fn default() -> Self {
        SafeRBTreeStorage::new(SafeRBTreeNode::new_root())
    }
}

impl SafeRBTreeStorage {
    pub fn new(node: SafeRBTreeNode) -> SafeRBTreeStorage {
        SafeRBTreeStorage {
            domain_tree: Arc::new(RwLock::new(node)),
            fast_cache: DashMap::new(),
        }
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
    ) -> Result<Arc<RwLock<SafeRBTreeNode>>, OtterError> {
        let parser = ZoneFileParser::new(file)?;
        let reader = ZoneReader::new(parser, default_origin);
        let mut first_rr = None;
        let mut start_point = None;
        for item in reader {
            match item {
                Ok(rr) => {
                    // insert rr record to zone node.
                    if first_rr.is_none() {
                        if rr.get_type() != DNSType::SOA {
                            return Err(OtterError::StorageError(
                                StorageError::NotStartWithSOARecord,
                            ));
                        }
                        first_rr = Some(rr.clone());
                        start_point = Some(self.insert_rr(rr)?);
                    } else {
                        if rr.get_type() == DNSType::SOA {
                            return Err(OtterError::StorageError(StorageError::TooManySOARecords));
                        }
                        self.insert_rr(rr)?;
                    }
                }
                Err(err) => return Err(OtterError::DNSProtoError(err)),
            }
        }
        if first_rr.is_none() || start_point.is_none() {
            return Err(OtterError::StorageError(StorageError::SOAResourceError));
        }
        Ok(start_point.unwrap())
    }

    /// locate the dns name node from top zone root node. if the dns name is not found in this zone
    /// create a sub node based the label.
    /// should valid if the name is below to the zone data.
    pub fn find_or_insert(
        &mut self,
        name: &DNSName,
    ) -> Result<Arc<RwLock<SafeRBTreeNode>>, StorageError> {
        let current_name = &self.domain_tree.read().unwrap().get_name();
        // domain not belong to this zone
        if !name.is_part_of(current_name) {
            return Err(StorageError::ZoneOutOfArea(
                name.to_string(),
                current_name.to_string(),
            ));
        }
        let mut labels_count = name.label_count();
        if labels_count == 0 {
            return Ok(self.domain_tree.clone());
        }
        let mut parent_node = None;
        let mut current = self.domain_tree.clone();

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

    pub fn insert_rr(
        &mut self,
        rr: ResourceRecord,
    ) -> Result<Arc<RwLock<SafeRBTreeNode>>, StorageError> {
        let dname = rr.get_dname();
        let vnode = self.find_or_insert(dname)?;
        vnode.write().unwrap().add_rr(rr)?;
        Ok(vnode)
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
        let name = self.domain_tree.read().unwrap().get_name();
        match self.domain_tree.write().unwrap().rr_sets.remove(&dtype) {
            Some(_) => Ok(()),
            None => Err(StorageError::DNSTypeNotFoundError(
                name.to_string(),
                dtype.to_string(),
            )),
        }
    }

    pub fn find_best(&self, name: &DNSName) -> Option<Arc<RwLock<SafeRBTreeNode>>> {
        let mut labels_count = name.label_count();
        if labels_count == 0 {
            if !self.domain_tree.read().unwrap().auth_data {
                return None;
            }
            return Some(self.domain_tree.clone());
        }
        let mut current = self.domain_tree.clone();
        for label in name.labels.iter().rev() {
            labels_count -= 1;
            let temp = current.clone();
            let subtree = temp.read().unwrap().subtree.clone();
            let subtree = subtree.read().unwrap();
            let result = subtree.get(&label.clone());
            /// subtree exist and has label node
            if let Some(node) = result {
                if labels_count == 0 {
                    if !node.read().unwrap().auth_data {
                        return None;
                    }
                    return Some(node.clone());
                }
                current = node.clone();
                continue;
            }
            if !current.read().unwrap().auth_data {
                return None;
            }
            return Some(current);
        }
        if !self.domain_tree.read().unwrap().auth_data {
            return None;
        }
        Some(current)
    }
    pub fn find_smallest(
        &self,
        stack: &mut Vec<Arc<RwLock<SafeRBTreeNode>>>,
    ) -> Arc<RwLock<SafeRBTreeNode>> {
        let current = self.domain_tree.clone();
        let subtree = current.read().unwrap().subtree.clone();
        if let Some((_, val)) = subtree.read().unwrap().iter().next() {
            stack.push(current);
            let subtree = SafeRBTreeStorage {
                domain_tree: val.clone(),
                fast_cache: DashMap::new(),
            };
            return subtree.find_smallest(stack);
        }
        current
    }
    pub fn get_additionals(&self, names: Vec<&DNSName>) -> Vec<Arc<RwLock<RRSet>>> {
        // TODO: if name is not in current zone , do we need to return the glue records, maybe ignore it.
        let mut results = vec![];
        for name in names.iter() {
            if !self.is_own_domain(name) {
                continue;
            }
            if let Ok(result) = self.find(name) {
                let node = result.read().unwrap();
                if let Some(result) = node.rr_sets.get(&DNSType::A) {
                    results.push(result.value().clone());
                }
                if let Some(result) = node.rr_sets.get(&DNSType::AAAA) {
                    results.push(result.value().clone());
                };
            }
        }
        results
    }

    pub fn is_own_domain(&self, name: &DNSName) -> bool {
        let zone = self.domain_tree.read().unwrap().get_name();
        let (is_relative, _) = name.is_relative(&zone);
        is_relative
    }

    pub fn find(&self, name: &DNSName) -> Result<Arc<RwLock<SafeRBTreeNode>>, StorageError> {
        let mut labels_count = name.label_count();
        if labels_count == 0 {
            if !self.domain_tree.read().unwrap().auth_data {
                return Err(StorageError::RefusedError);
            }
            return Ok(self.domain_tree.clone());
        }
        let mut current = self.domain_tree.clone();
        for label in name.labels.iter().rev() {
            labels_count -= 1;
            let temp = current.clone();
            let subtree = temp.read().unwrap().subtree.clone();
            /// subtree exist and has label node
            if let Some(node) = subtree.read().unwrap().get(&label.clone()) {
                if labels_count == 0 {
                    if !node.read().unwrap().auth_data {
                        return Err(StorageError::RefusedError);
                    }
                    return Ok(node.clone());
                }
                current = node.clone();
                continue;
            }
            if let Some(node) = subtree.read().unwrap().get(&WILDCARD_LABEL) {
                return Ok(node.clone());
            }
            /// not found in subtree
            if !current.read().unwrap().auth_data {
                return Err(StorageError::RefusedError);
            }
            return Err(StorageError::DomainNotFoundError(name.to_string()));
        }
        if !current.read().unwrap().auth_data {
            return Err(StorageError::RefusedError);
        }
        Ok(current)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::safe_rbtree::SafeRBTreeNode;
    use dnsproto::dnsname::DNSName;
    use otterlib::errors::StorageError;

    fn get_example_zone() -> SafeRBTreeStorage {
        let test_zone_file = "./test/example.zone";
        let storage = SafeRBTreeStorage::new_zone_from_file(test_zone_file, None).unwrap();
        storage
    }

    #[test]
    fn test_get_additionals() {
        let node = SafeRBTreeNode::new_root();
        let zone = SafeRBTreeStorage::new(node);
        let dnames = vec![
            DNSName::new("ns1.google.com.", None).unwrap(),
            DNSName::new("ns1.google.com.", None).unwrap(),
        ];
        let result = zone.get_additionals(dnames.iter().collect());
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_find_node() {
        let zone = get_example_zone();
        // in zone
        let test_domain = &DNSName::new("example.com.", None).unwrap();
        assert_eq!(zone.find(test_domain).is_ok(), true);
        // in zone but not exist
        let test_domain = &DNSName::new("not_exist.example.com.", None).unwrap();
        assert_eq!(
            zone.find(test_domain).unwrap_err(),
            StorageError::DomainNotFoundError("not_exist.example.com.".to_string())
        );
        // out of zone
        let test_domain = &DNSName::new("outofzone.com.", None).unwrap();
        assert_eq!(
            zone.find(test_domain).unwrap_err(),
            StorageError::RefusedError
        );
    }

    #[test]
    fn test_find_best_zone() {
        let zone = get_example_zone();
        // eprintln!("{}", zone.0.read().unwrap().get_name().to_string());
        let find_result = zone.find_best(&DNSName::new("example.com.", None).unwrap());
        assert_eq!(find_result.is_some(), true);
        let find_result = find_result.unwrap();
        assert_eq!(
            find_result.read().unwrap().get_name().to_string(),
            "example.com.".to_string()
        );
        let find_result = zone.find_best(&DNSName::new("notexist.example.com.", None).unwrap());
        assert_eq!(find_result.is_some(), true);
        let find_result = find_result.unwrap();
        assert_eq!(
            find_result.read().unwrap().get_name().to_string(),
            "example.com.".to_string()
        );
        let find_result = zone.find_best(&DNSName::new("www.notexist.example.com.", None).unwrap());
        assert_eq!(find_result.is_some(), true);
        let find_result = find_result.unwrap();
        assert_eq!(
            find_result.read().unwrap().get_name().to_string(),
            "example.com.".to_string()
        );

        // should return refused.
        let find_result = zone.find_best(&DNSName::new("xay.com.", None).unwrap());
        assert_eq!(find_result.is_some(), false);

        let find_result = zone.find_best(&DNSName::new("com.", None).unwrap());
        assert_eq!(find_result.is_some(), false);
        let find_result = zone.find_best(&DNSName::new(".", None).unwrap());
        assert_eq!(find_result.is_some(), false);
    }
}
