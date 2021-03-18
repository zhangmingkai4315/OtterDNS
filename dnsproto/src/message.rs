// http://www.networksorcery.com/enp/protocol/dns.htm
use crate::dnsname::{parse_name, DNSName};
use crate::edns::EDNS;
use crate::errors::DNSProtoErr;
use crate::meta::{Answer, Header, OpCode, Question, RCode};
use crate::meta::{DNSClass, DNSType};
use crate::qtype::DNSTypeOpt;
use nom::number::complete::{be_u16, be_u32};
use std::collections::HashMap;
use std::convert::TryFrom;
#[derive(Debug, PartialEq)]
pub struct Message {
    header: Header,
    questions: Vec<Question>,
    answers: Vec<Record>,
    authorities: Vec<Record>,
    additional: Vec<Record>,
}

named!(parse_question<&[u8], Question>,
    do_parse!(
        name: call!(parse_name, &[]) >>
        qtype: be_u16 >>
        qclass: be_u16 >>
        ( Question {
            q_name: name,
            q_type: DNSType::try_from(qtype).unwrap(),
            q_class: DNSClass::try_from(qclass).unwrap(),
        })
    )
);

#[derive(Debug, PartialEq)]
pub enum Record {
    AnswerRecord(Answer),
    EDNSRecord(EDNS),
}

named_args!(parse_answer<'a>(original: &[u8])<&'a [u8], Record>,
    do_parse!(
        name: call!(parse_name, original)>>
        qtype: be_u16 >>
        qclass: be_u16 >>
        ttl:  be_u32 >>
        data_length: be_u16>>
        data: take!(data_length)>>
        value: value!(match qtype == 41 {
            true => Record::EDNSRecord(EDNS{
                name,
                qtype: DNSType::OPT,
                payload_size: qclass,
                extension: (ttl & 0xff000000 >> 24 )as u8,
                version: (ttl & 0x00ff0000 >> 16 )as u8,
                do_bit: (ttl & 0x0000ff00 >> 15) == 1,
                raw_data: data.to_vec(),
                data: None,
            }),
            false => {
                let qtype = DNSType::try_from(qtype).unwrap();
                Record::AnswerRecord(Answer{
                    data:None,
                    name,
                    qtype,
                    qclass: DNSClass::try_from(qclass).unwrap(),
                    ttl,
                    raw_data: data.to_vec(),
                })
            }
        }) >>
        (value)
    )
);

named!(parse_flags<&[u8],(u8,u8,u8,u8,u8,u8,u8,u8,u8,u8)>,
    bits!(tuple!(take_bits!(1u8),
          take_bits!(4u8),  take_bits!(1u8),  take_bits!(1u8),
          take_bits!(1u8),  take_bits!(1u8),  take_bits!(1u8),
          take_bits!(1u8),  take_bits!(1u8),  take_bits!(4u8))));

named!(parse_header_frame<&[u8], Header>,
    do_parse!(
        transaction_id: be_u16 >>
        flags:  parse_flags >>
        questions_length: be_u16 >>
        answer_length: be_u16 >>
        ns_length: be_u16 >>
        addition_length: be_u16 >>
        (Header {
            id: transaction_id,
            qr: flags.0 == 1,
            op_code: OpCode::from(flags.1),
            aa: flags.2 == 1,
            tc: flags.3 == 1,
            rd: flags.4 == 1,
            ra: flags.5 == 1,
            z: flags.6 == 1,
            ad: flags.7 == 1,
            cd: flags.8 == 1,
            r_code: RCode::from(flags.9),
            question_count: questions_length,
            answer_count: answer_length,
            ns_count:  ns_length,
            additional_count: addition_length,
         })
    )
);

pub fn parse_dns_message(message: &[u8]) -> Result<Message, DNSProtoErr> {
    match parse_message(message, message) {
        Ok(val) => Ok(val.1),
        Err(_) => Err(DNSProtoErr::PacketParseError),
    }
}

named_args!(parse_message<'a>(original: &[u8])<&'a [u8], Message>,
    do_parse!(
        header:  parse_header_frame >>
        questions: many_m_n!(header.question_count as usize,header.question_count as usize, parse_question) >>
        answers: many_m_n!(header.answer_count as usize,header.answer_count as usize, call!(parse_answer,original)) >>
        authorities: many_m_n!(header.ns_count as usize,header.ns_count as usize, call!(parse_answer,original))>>
        additional:  many_m_n!(header.additional_count as usize,header.additional_count as usize, call!(parse_answer, original)) >>
        (Message{
            header,
            questions,
            answers,
            authorities,
            additional,
        })
    )
);

#[test]
fn test_parse_header() {
    let bytes = [
        0x2b, 0x01, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x63, 0x6f,
        0x6d, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];

    let result = parse_header_frame(&bytes);
    assert!(result.is_ok(), true);

    let header = Header {
        id: 0x2b01,
        qr: false,
        op_code: OpCode::Query,
        aa: false,
        tc: false,
        rd: true,
        ra: false,
        z: false,
        ad: true,
        cd: false,
        r_code: RCode::NoError,
        question_count: 1,
        answer_count: 0,
        ns_count: 0,
        additional_count: 1,
    };

    assert_eq!(result.unwrap().1, header);

    let bytes = [
        0x8e, 0xd0, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x04, 0x50, 0x41,
        0x55, 0x4c, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x2a,
        0x30, 0x00, 0x40, 0x01, 0x61, 0x0c, 0x72, 0x6f, 0x6f, 0x74, 0x2d, 0x73, 0x65, 0x72, 0x76,
        0x65, 0x72, 0x73, 0x03, 0x6e, 0x65, 0x74, 0x00, 0x05, 0x6e, 0x73, 0x74, 0x6c, 0x64, 0x0c,
        0x76, 0x65, 0x72, 0x69, 0x73, 0x69, 0x67, 0x6e, 0x2d, 0x67, 0x72, 0x73, 0x03, 0x63, 0x6f,
        0x6d, 0x00, 0x78, 0x68, 0x7a, 0x68, 0x00, 0x00, 0x07, 0x08, 0x00, 0x00, 0x03, 0x84, 0x00,
        0x09, 0x3a, 0x80, 0x00, 0x01, 0x51, 0x80,
    ];

    let header = Header {
        id: 0x8ed0,
        qr: true,
        op_code: OpCode::Query,
        aa: false,
        tc: false,
        rd: true,
        ra: true,
        z: false,
        ad: false,
        cd: false,
        r_code: RCode::NameError,
        question_count: 1,
        answer_count: 0,
        ns_count: 1,
        additional_count: 0,
    };
    let result = parse_header_frame(&bytes);
    assert_eq!(result.is_ok(), true);
    assert_eq!(result.unwrap().1, header);
}

#[test]
fn test_parse_question() {
    let a = [
        0x07, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x04, 0x6c, 0x69, 0x76, 0x65, 0x03, 0x63,
        0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
    ];

    let result = parse_question(&a);
    let question = Question {
        q_name: DNSName {
            is_fqdn: true,
            labels: vec![
                String::from("storage"),
                String::from("live"),
                String::from("com"),
            ],
        },
        q_type: DNSType::A,
        q_class: DNSClass::IN,
    };
    assert_eq!(result.is_ok(), true);
    assert_eq!(result.unwrap().1, question);
}
#[test]
fn test_parse_answer() {
    let answer = [
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x40, 0x00, 0x04, 0x45, 0xab, 0xe4,
        0x14,
    ];

    let original = [
        0xa4, 0xac, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x04, 0x00, 0x09, 0x03, 0x77, 0x77,
        0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01,
        0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x40, 0x00, 0x04, 0x45,
        0xab, 0xe4, 0x14, 0xc0, 0x10, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0x63, 0xa9, 0x00, 0x06,
        0x03, 0x6e, 0x73, 0x33, 0xc0, 0x10, 0xc0, 0x10, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0x63,
        0xa9, 0x00, 0x06, 0x03, 0x6e, 0x73, 0x31, 0xc0, 0x10, 0xc0, 0x10, 0x00, 0x02, 0x00, 0x01,
        0x00, 0x02, 0x63, 0xa9, 0x00, 0x06, 0x03, 0x6e, 0x73, 0x34, 0xc0, 0x10, 0xc0, 0x10, 0x00,
        0x02, 0x00, 0x01, 0x00, 0x02, 0x63, 0xa9, 0x00, 0x06, 0x03, 0x6e, 0x73, 0x32, 0xc0, 0x10,
        0xc0, 0x4e, 0x00, 0x01, 0x00, 0x01, 0x00, 0x04, 0xf7, 0xa8, 0x00, 0x04, 0xd8, 0xef, 0x20,
        0x0a, 0xc0, 0x4e, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x01, 0x89, 0xa5, 0x00, 0x10, 0x20, 0x01,
        0x48, 0x60, 0x48, 0x02, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0xc0,
        0x72, 0x00, 0x01, 0x00, 0x01, 0x00, 0x04, 0xf7, 0xa8, 0x00, 0x04, 0xd8, 0xef, 0x22, 0x0a,
        0xc0, 0x72, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x01, 0x89, 0xa5, 0x00, 0x10, 0x20, 0x01, 0x48,
        0x60, 0x48, 0x02, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0xc0, 0x3c,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x04, 0xf7, 0xa8, 0x00, 0x04, 0xd8, 0xef, 0x24, 0x0a, 0xc0,
        0x3c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x1e, 0xcf, 0x00, 0x10, 0x20, 0x01, 0x48, 0x60,
        0x48, 0x02, 0x00, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0xc0, 0x60, 0x00,
        0x01, 0x00, 0x01, 0x00, 0x04, 0xf7, 0xa8, 0x00, 0x04, 0xd8, 0xef, 0x26, 0x0a, 0xc0, 0x60,
        0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x1e, 0xcf, 0x00, 0x10, 0x20, 0x01, 0x48, 0x60, 0x48,
        0x02, 0x00, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x29, 0x10,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let a = parse_answer(&answer, &original);
    assert_eq!(a.as_ref().is_ok(), true);
    let result = Record::AnswerRecord(Answer {
        name: DNSName {
            is_fqdn: true,
            labels: vec![
                String::from("www"),
                String::from("google"),
                String::from("com"),
            ],
        },
        qtype: DNSType::A,
        qclass: DNSClass::IN,
        ttl: 64,
        raw_data: vec![69, 171, 228, 20],
        data: None,
    });
    assert_eq!(result, a.unwrap().1);

    let answer = [
        0xc0, 0x10, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0x63, 0xa9, 0x00, 0x06, 0x03, 0x6e, 0x73,
        0x33, 0xc0, 0x10,
    ];

    let a = parse_answer(&answer, &original);
    let result = Record::AnswerRecord(Answer {
        name: DNSName {
            is_fqdn: true,
            labels: vec![String::from("google"), String::from("com")],
        },
        qtype: DNSType::NS,
        qclass: DNSClass::IN,
        ttl: 156585,
        raw_data: vec![0x03, 0x6e, 0x73, 0x33, 0xc0, 0x10],
        data: None,
    });
    assert_eq!(result, a.unwrap().1);

    let edns = [
        0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let a = parse_answer(&edns, &original);
    let result = Record::EDNSRecord(EDNS {
        name: DNSName {
            is_fqdn: true,
            labels: vec![],
        },
        qtype: DNSType::OPT,
        payload_size: 4096,
        extension: 0,
        version: 0,
        do_bit: false,
        raw_data: vec![],
        data: None,
    });
    assert_eq!(result, a.unwrap().1);
}

#[test]
fn test_parse_message() {
    let a = [
        0xa4, 0xac, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x77, 0x77,
        0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01,
        0x00, 0x01, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let result = parse_message(&a, &a);
    assert_eq!(result.as_ref().is_ok(), true);
    let a = [
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
    let result = parse_message(&a, &a);
    assert_eq!(result.as_ref().is_ok(), true);

    let a = [];
    let result = parse_message(&a, &a);
    assert_eq!(result.as_ref().is_err(), true);
}

#[test]
fn test_encode_header() {
    let header = Header {
        id: 0x2b01,
        qr: false,
        op_code: OpCode::Query,
        aa: false,
        tc: false,
        rd: true,
        ra: false,
        z: false,
        ad: true,
        cd: false,
        r_code: RCode::NoError,
        question_count: 1,
        answer_count: 0,
        ns_count: 0,
        additional_count: 1,
    };
    let mut bin_message = vec![];
    match header.encode(&mut bin_message) {
        Ok(_offset) => {
            assert_eq!(
                bin_message,
                vec![0x2b, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
            );
        }
        Err(err) => {
            assert!(false, "should not return err: {}", err.to_string());
        }
    }
}

#[test]
fn test_encode_question() {
    let question = Question {
        q_name: DNSName::new("com").unwrap(),
        q_type: DNSType::NS,
        q_class: DNSClass::IN,
    };
    let mut bin_message: Vec<u8> = vec![];

    match question.encode(&mut bin_message, 0, None) {
        Ok(offset) => {
            assert_eq!(offset, 9);
            assert_eq!(bin_message, vec![3, 99, 111, 109, 0, 0, 2, 0, 1]);
        }
        Err(e) => assert!(false, format!("error: {}", e.to_string())),
    }

    let question = Question {
        q_name: DNSName::new("google.com").unwrap(),
        q_type: DNSType::NS,
        q_class: DNSClass::IN,
    };

    let mut compression = HashMap::new();
    compression.insert("com".to_owned(), 2usize);
    let compression = Some((&mut compression, 0));
    let mut bin_message: Vec<u8> = vec![];
    match question.encode(&mut bin_message, 0, compression) {
        Ok(offset) => {
            assert_eq!(offset, 13);
            assert_eq!(
                bin_message,
                vec![6, 103, 111, 111, 103, 108, 101, 192, 2, 0, 2, 0, 1]
            );
        }
        Err(e) => assert!(false, format!("error: {}", e.to_string())),
    }
}

#[test]
fn test_encode_answer() {
    use crate::qtype::DnsTypeNS;
    let nsdata = DnsTypeNS {
        ns: DNSName::new("b.gtld-servers.net").unwrap(),
    };

    let mut answer = Answer {
        ttl: 256,
        name: DNSName::new("com").unwrap(),
        qtype: DNSType::NS,
        qclass: DNSClass::IN,
        raw_data: vec![],
        data: Some(Box::new(nsdata)),
    };

    let mut bin_message: Vec<u8> = vec![];
    match answer.encode(&mut bin_message, 0, None) {
        Ok(offset) => {
            assert_eq!(offset, 35);
            // println!("{:02X?}", bin_message);
            assert_eq!(
                bin_message,
                vec![
                    3, 99, 111, 109, 0, 0, 2, 0, 1, 0, 0, 1, 0, 0, 20, 1, 98, 12, 103, 116, 108,
                    100, 45, 115, 101, 114, 118, 101, 114, 115, 3, 110, 101, 116, 0
                ]
            );
        }
        Err(e) => assert!(false, format!("error: {}", e.to_string())),
    }

    // let question = Question{
    //     q_name: DNSName::new("google.com").unwrap(),
    //     q_type: DNSType::NS,
    //     q_class: DNSClass::IN,
    // };
    //
    let mut compression = HashMap::new();
    compression.insert("gtld-servers.net".to_owned(), 2usize);
    let compression = Some(&mut compression);
    let mut bin_message: Vec<u8> = vec![];
    match answer.encode(&mut bin_message, 0, compression) {
        Ok(offset) => {
            assert_eq!(offset, 19);
            assert_eq!(
                bin_message,
                vec![3, 99, 111, 109, 0, 0, 2, 0, 1, 0, 0, 1, 0, 0, 4, 1, 98, 192, 2]
            );
        }
        Err(e) => {
            assert!(false, format!("error: {}", e.to_string()))
        }
    }
}

#[test]
fn test_encode_edns_message() {
    let mut edns = EDNS {
        name: Default::default(),
        qtype: DNSType::OPT,
        payload_size: 512,
        extension: 0,
        version: 0,
        do_bit: true,
        raw_data: vec![],
        data: Some(Box::new(DNSTypeOpt::default())),
    };
    let mut data = vec![];

    match edns.encode(&mut data, 0, None) {
        Ok(_) => {
            assert_eq!(
                data.clone(),
                vec![0, 0, 41, 2, 0, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0]
            );
        }
        Err(e) => {
            assert!(false, format!("{:?}", e));
        }
    }
}

#[test]
fn test_encode_message() {
    // let message = Message{
    //     header: Header::new(),
    //     questions: vec![],
    //     answers: vec![],
    //     authorities: vec![],
    //     additional: vec![]
    // }
}
