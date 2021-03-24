extern crate storage;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dnsproto::dnsname::DNSName;
use dnsproto::meta::{DNSClass, DNSType, ResourceRecord};
use dnsproto::qtype::DnsTypeA;
use storage::rb_storage::RBZone;

fn rbstorage_find_name(c: &mut Criterion) {
    let mut zone = RBZone::new_root();
    let rr = ResourceRecord::new(
        "baidu.com",
        DNSType::A,
        DNSClass::IN,
        1000,
        Some(Box::new(DnsTypeA::new("1.1.1.1").unwrap())),
    )
    .unwrap();
    zone.insert(rr);
    let name = DNSName::new("baidu.com").unwrap();
    c.bench_function("storage_search", |b| {
        b.iter(|| match zone.find(&name) {
            Ok(_) => {}
            Err(err) => panic!(err),
        })
    });
}

criterion_group!(storage_benches, rbstorage_find_name,);
criterion_main!(storage_benches);
