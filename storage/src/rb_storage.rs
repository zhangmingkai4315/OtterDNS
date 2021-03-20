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

struct RBTreeNode {
    label: String,
    // TODO: How to save different type for quick search and retirve.
    data: Vec<ResourceRecord>,
    subtree: Option<RBTree<String, RBTreeNode>>,
}

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
        // let mut labels = rr.get_labels()?;
        // let ref mut current = self.root;
        // let mut found = false;
        // for i in rr.name.labels.iter().rev(){
        //    if current.subtree.is_none(){
        //        break
        //    }
        //    let result = current.subtree.unwrap().get(i.as_ref()).as_mut();
        //     current = result.unwrap();
        //     if result.is_some(){
        //
        //    }else{
        //        break
        //    };
        //
        // }
        Ok(())
    }

    fn delete(&mut self, qtype: DNSType, domain: &DNSName) -> Result<(), StorageError> {
        unimplemented!()
    }

    fn get_soa(&mut self, domain: &DNSName) -> Result<DnsTypeSOA, StorageError> {
        unimplemented!()
    }
}

// #[derive(Clone)]
// struct DNSRBNode<'a> {
//     link: RBTreeLink,
//     key: &'a str,
//     value: Box<ResourceRecord>,
// }
//
// // intrusive_adapter!(DNSAdapter<'a> = &'a DNSRBNode: DNSRBNode { link: RBTreeLink });
// intrusive_adapter!(ElementAdapter = Box<DNSRBNode<'a>>: DNSRBNode<'a> { link: RBTreeLink });
//
// impl<'a, 'b> KeyAdapter<'a, 'b> for ElementAdapter {
//     type Key = String;
//     fn get_key(&self, x: &'a DNSRBNode<'b>) -> &str { x.key }
// }
//
//
// fn get_rb_node(domain: &str, qtype: DNSType, qclass: DNSClass)->DNSRBNode{
//     DNSRBNode{
//         link: Default::default(),
//         key: domain,
//         value: Box::new(ResourceRecord::new(domain, qtype,qclass, 1,None).unwrap())
//     }
// }
//
// #[test]
// fn test_rb_tree(){
//
//     let mut l = RBTree::new(ObjAdapter::new());
//     let dnsnode = get_rb_node("baidu1.com", DNSType::A, DNSClass::IN);
//     l.insert(&dnsnode);
//     let dnsnode = get_rb_node("baidu2.com", DNSType::A, DNSClass::IN);
//     l.insert(&dnsnode);
//     let dnsnode = get_rb_node("baidu3.com", DNSType::A, DNSClass::IN);
//     l.insert(&dnsnode);
//
//     println!("{:?}",l.find("baidu1.com").get().unwrap())
// }
