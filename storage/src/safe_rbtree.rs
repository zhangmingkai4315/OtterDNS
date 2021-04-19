use crate::unsafe_rbtree::{RBTreeNode, UnSafeRBTreeStorage};
use dnsproto::dnsname::DNSName;
use dnsproto::meta::{DNSType, RRSet, ResourceRecord};
use otterlib::errors::{OtterError, StorageError};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub struct SafeRBTree {
    shared: Arc<Mutex<UnSafeRBTreeStorage>>,
}
unsafe impl Send for SafeRBTree {}
impl SafeRBTree {
    pub fn new(node: RBTreeNode) -> SafeRBTree {
        let shared = Arc::new(Mutex::new(UnSafeRBTreeStorage::new(node)));
        SafeRBTree { shared }
    }
    pub fn new_zone_from_file(
        file: &str,
        default_origin: Option<String>,
    ) -> Result<SafeRBTree, OtterError> {
        let zone = UnSafeRBTreeStorage::new_zone_from_file(file, default_origin)?;
        let shared = Arc::new(Mutex::new(zone));
        Ok(SafeRBTree { shared })
    }
    pub fn update_zone(
        &mut self,
        file: &str,
        default_origin: Option<String>,
    ) -> Result<(), OtterError> {
        let mut storage = self.shared.lock().unwrap();
        storage.update_zone(file, default_origin)
    }
    pub fn search_rrset(
        &mut self,
        dname: &DNSName,
        dtype: DNSType,
    ) -> Result<Rc<RefCell<RRSet>>, StorageError> {
        let mut storage = self.shared.lock().unwrap();
        storage.search_rrset(dname, dtype)
    }

    pub fn insert_rr(&mut self, rr: ResourceRecord) -> Result<(), StorageError> {
        let mut storage = self.shared.lock().unwrap();
        storage.insert_rr(rr)
    }
}

impl Default for SafeRBTree {
    fn default() -> Self {
        SafeRBTree::new(RBTreeNode::new_root())
    }
}
