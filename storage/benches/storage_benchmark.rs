extern crate storage;
use criterion::{criterion_group, criterion_main, Criterion};
use dnsproto::dnsname::DNSName;
use dnsproto::meta::{DNSClass, DNSType, ResourceRecord};
use dnsproto::qtype::DnsTypeA;
use storage::safe_rbtree::SafeRBTree;
use storage::unsafe_rbtree::UnSafeRBTreeStorage;

fn unsafe_rbtree_search(c: &mut Criterion) {
    let mut zone = UnSafeRBTreeStorage::default();
    let rr = ResourceRecord::new(
        "baidu.com.",
        DNSType::A,
        DNSClass::IN,
        1000,
        Some(Box::new(DnsTypeA::new("1.1.1.1").unwrap())),
    )
    .unwrap();
    let _ = zone.insert_rr(rr);
    let name = DNSName::new("baidu.com.", None).unwrap();
    c.bench_function("unsafe_rbtree_search", |b| {
        b.iter(|| match zone.search_rrset(&name, DNSType::A) {
            Ok(_) => {}
            Err(err) => panic!(err),
        })
    });
}

fn safe_rbtree_search(c: &mut Criterion) {
    let mut zone = SafeRBTree::default();
    let rr = ResourceRecord::new(
        "baidu.com.",
        DNSType::A,
        DNSClass::IN,
        1000,
        Some(Box::new(DnsTypeA::new("1.1.1.1").unwrap())),
    )
    .unwrap();
    let _ = zone.insert_rr(rr);
    let name = DNSName::new("baidu.com.", None).unwrap();
    c.bench_function("safe_rbtree_search", |b| {
        b.iter(|| match zone.search_rrset(&name, DNSType::A) {
            Ok(_) => {}
            Err(err) => panic!(err),
        })
    });
}

criterion_group!(storage_benches, unsafe_rbtree_search, safe_rbtree_search);
criterion_main!(storage_benches);
