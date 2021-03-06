extern crate dnsproto;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

use dnsproto::edns::EDNS;
use dnsproto::message::Message;
use dnsproto::meta::{DNSClass, DNSType, Header, Question, ResourceRecord};
use dnsproto::qtype::{DnsTypeA, DnsTypeNS, DnsTypeOpt};

fn dns_parse_message(c: &mut Criterion) {
    let message = [
        0x8e, 0x28, 0x81, 0x80, 0x00, 0x01, 0x00, 0x08, 0x00, 0x06, 0x00, 0x07, 0x07, 0x67, 0x61,
        0x74, 0x65, 0x77, 0x61, 0x79, 0x02, 0x66, 0x65, 0x09, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x2d,
        0x64, 0x6e, 0x73, 0x02, 0x63, 0x6e, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x36, 0x00, 0x04, 0x11, 0xfa, 0x78, 0x11, 0xc0, 0x0c, 0x00,
        0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x36, 0x00, 0x04, 0x11, 0xf8, 0x98, 0x0d, 0xc0, 0x0c,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x36, 0x00, 0x04, 0x11, 0xf8, 0x98, 0x68, 0xc0,
        0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x36, 0x00, 0x04, 0x11, 0xf8, 0x98, 0x88,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x36, 0x00, 0x04, 0x11, 0xf8, 0x9e,
        0xb5, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x36, 0x00, 0x04, 0x11, 0xf8,
        0x9f, 0x94, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x36, 0x00, 0x04, 0x11,
        0xf8, 0x9f, 0xce, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x36, 0x00, 0x04,
        0x11, 0xf8, 0x9f, 0xec, 0xc0, 0x14, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x08, 0xf3, 0x00,
        0x19, 0x06, 0x6e, 0x73, 0x2d, 0x31, 0x36, 0x30, 0x0c, 0x61, 0x77, 0x73, 0x64, 0x6e, 0x73,
        0x2d, 0x63, 0x6e, 0x2d, 0x31, 0x30, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0xc0, 0x14, 0x00, 0x02,
        0x00, 0x01, 0x00, 0x00, 0x08, 0xf3, 0x00, 0x1a, 0x07, 0x6e, 0x73, 0x2d, 0x32, 0x35, 0x32,
        0x32, 0x0c, 0x61, 0x77, 0x73, 0x64, 0x6e, 0x73, 0x2d, 0x63, 0x6e, 0x2d, 0x32, 0x39, 0x03,
        0x62, 0x69, 0x7a, 0x00, 0xc0, 0x14, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x08, 0xf3, 0x00,
        0x1c, 0x0c, 0x6e, 0x73, 0x2d, 0x69, 0x6e, 0x74, 0x6c, 0x2d, 0x33, 0x38, 0x33, 0x36, 0x0c,
        0x61, 0x77, 0x73, 0x64, 0x6e, 0x73, 0x2d, 0x63, 0x6e, 0x2d, 0x34, 0x37, 0xc0, 0x21, 0xc0,
        0x14, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x08, 0xf3, 0x00, 0x0a, 0x07, 0x6e, 0x73, 0x2d,
        0x33, 0x38, 0x33, 0x36, 0xc1, 0x0d, 0xc0, 0x14, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x08,
        0xf3, 0x00, 0x1a, 0x07, 0x6e, 0x73, 0x2d, 0x31, 0x36, 0x32, 0x39, 0x0c, 0x61, 0x77, 0x73,
        0x64, 0x6e, 0x73, 0x2d, 0x63, 0x6e, 0x2d, 0x33, 0x37, 0x03, 0x6e, 0x65, 0x74, 0x00, 0xc0,
        0x14, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x08, 0xf3, 0x00, 0x0e, 0x0b, 0x6e, 0x73, 0x2d,
        0x69, 0x6e, 0x74, 0x6c, 0x2d, 0x31, 0x36, 0x30, 0xc0, 0xbc, 0xc0, 0xb5, 0x00, 0x01, 0x00,
        0x01, 0x00, 0x00, 0x08, 0xf3, 0x00, 0x04, 0x34, 0x52, 0xb0, 0xa0, 0xc1, 0x3e, 0x00, 0x01,
        0x00, 0x01, 0x00, 0x00, 0x08, 0xf3, 0x00, 0x04, 0x34, 0x52, 0xb6, 0x5d, 0xc0, 0xda, 0x00,
        0x01, 0x00, 0x01, 0x00, 0x00, 0x08, 0xf4, 0x00, 0x04, 0x36, 0xde, 0x21, 0xda, 0xc1, 0x28,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x08, 0xf3, 0x00, 0x04, 0x36, 0xde, 0x26, 0xfc, 0xc1,
        0x64, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x08, 0xf3, 0x00, 0x04, 0x34, 0x2e, 0xb8, 0xa0,
        0xc1, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x08, 0xf3, 0x00, 0x04, 0x34, 0x2e, 0xb6,
        0xfc, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    c.bench_function("decode_message", |b| {
        b.iter(|| Message::parse_dns_message(&message))
    });
}

fn dns_encode_answer_message(c: &mut Criterion) {
    let mut header = Header::new();
    header.set_id(0xcab1);
    header.set_rd(true);
    // serialize a question
    let question = Question::new("google.com.", DNSType::NS, DNSClass::IN).unwrap();
    let edns = EDNS::new();
    let mut message = Message::new_with_header(header);
    message.set_question(question);
    message.append_edns(edns);
    for ns in vec![
        "ns1.google.com.",
        "ns2.google.com.",
        "ns3.google.com.",
        "ns4.google.com.",
    ] {
        let answer = ResourceRecord::new(
            "google.com.",
            DNSType::NS,
            DNSClass::IN,
            10000,
            Some(Box::new(DnsTypeNS::new(ns).unwrap())),
        )
        .unwrap();
        message.append_answer(answer);
    }
    message.header.set_qr(true);
    message.header.set_rd(true);
    c.bench_function("encode_answer_message", |b| {
        b.iter(|| Message::encode(&mut message))
    });
}

fn dns_encode_question_message(c: &mut Criterion) {
    let mut header = Header::new();
    header.set_id(0xcab1);
    header.set_rd(true);
    // serialize a question
    let question = Question::new("google.com.", DNSType::NS, DNSClass::IN).unwrap();
    let edns = EDNS::new();
    let mut message = Message::new_with_header(header);
    message.set_question(question);
    message.append_edns(edns);
    message.header.set_qr(false);
    message.header.set_rd(true);
    c.bench_function("encode_question_message", |b| {
        b.iter(|| Message::encode(&mut message))
    });
}

criterion_group!(
    codec_benches,
    dns_parse_message,
    dns_encode_question_message,
    dns_encode_answer_message
);
criterion_main!(codec_benches);
