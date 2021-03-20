// a red-black-tree storage for store all dns data
// use intrusive_collections::{RBTree, intrusive_adapter, RBTreeLink, KeyAdapter};
// use std::cell::Cell;
use dnsproto::dnsname::DNSName;
use dnsproto::qtype::DNSWireFrame;
use dnsproto::meta::{ResourceRecord, DNSType, DNSClass};

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