// http://www.networksorcery.com/enp/protocol/dns.htm

use crate::dns::labels::DNSName;
use crate::dns::record::{DNSClass, DNSType};
use nom::number::complete::{be_u16, be_u32};
use std::convert::TryFrom;

#[derive(Debug, PartialEq, Eq)]
pub struct Header {
    id: u16,
    qr: bool,
    op_code: OpCode,
    aa: bool,
    tc: bool,
    rd: bool,
    ra: bool,
    z: bool,
    ad: bool,
    cd: bool,
    r_code: RCode,
    question_count: u16,
    answer_count: u16,
    ns_count: u16,
    additional_count: u16,
}

#[derive(Debug, PartialEq)]
pub struct Question {
    q_name: Option<DNSName>,
    q_type: DNSType,
    q_class: DNSClass,
}


#[derive(Debug, PartialEq)]
pub struct Answer{
    name: Option<DNSName>,
    qtype: DNSType,
    qclass: DNSClass,
    ttl: u32,
    data: Vec<u8>,
}

named!(parse_question<&[u8], Question>,
    do_parse!(
        name: take_till1!(|c| c == 0x00) >> take!(1)>>
        qtype: be_u16 >>
        qclass: be_u16 >>
        (Question {
            q_name: DNSName::new(name, &[]),
            q_type: DNSType::try_from(qtype).unwrap(),
            q_class: DNSClass::try_from(qclass).unwrap(),
        })
    )
);


named_args!(parse_answer<'a>(original: &[u8])<&'a [u8], Answer>,
    do_parse!(
        name: take_till1!(|c| c == 0x00) >> take!(1)>>
        qtype: be_u16 >>
        qclass: be_u16 >>
        ttl:  be_u32 >>
        data_length: be_u16>>
        data: take!(data_length)>>
        (Answer{
            name: DNSName::new(name, original),
            qtype: DNSType::try_from(qtype).unwrap(),
            qclass: DNSClass::try_from(qclass).unwrap(),
            ttl: ttl,
            data: data.to_vec(),
        })
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

#[derive(Debug, PartialEq, Eq)]
pub enum OpCode {
    Query,
    IQuery,
    Status,
    Reserved,
    Notify,
    Update,
}
impl From<u8> for OpCode {
    fn from(opcode: u8) -> Self {
        match opcode {
            0 => OpCode::Query,
            1 => OpCode::IQuery,
            2 => OpCode::Status,
            3 => OpCode::Reserved,
            4 => OpCode::Notify,
            5 => OpCode::Update,
            _ => OpCode::Reserved,
        }
    }
}

// http://www.tcpipguide.com/free/t_DNSMessageHeaderandQuestionSectionFormat.htm
#[derive(Debug, PartialEq, Eq)]
pub enum RCode {
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
    YxDomain,
    YxRRSet,
    NxRRSet,
    NotAuth,
    NotZone,
    Unknown,
}

impl From<u8> for RCode {
    fn from(rcode: u8) -> Self {
        match rcode {
            0 => RCode::NoError,
            1 => RCode::FormatError,
            2 => RCode::ServerFailure,
            3 => RCode::NameError,
            4 => RCode::NotImplemented,
            5 => RCode::Refused,
            6 => RCode::YxDomain,
            7 => RCode::YxRRSet,
            8 => RCode::NxRRSet,
            9 => RCode::NotAuth,
            10 => RCode::NotZone,
            _ => RCode::Unknown,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::dns::message::{parse_header_frame, Header, OpCode, RCode, parse_question, Question};
    use crate::dns::record::{DNSType, DNSClass};
    use crate::dns::labels::DNSName;

    #[test]
    fn parse_header() {
        let bytes = [
            0x2b, 0x01, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x63,
            0x6f, 0x6d, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
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
            0x8e, 0xd0, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x04, 0x50,
            0x41, 0x55, 0x4c, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x06, 0x00, 0x01, 0x00,
            0x00, 0x2a, 0x30, 0x00, 0x40, 0x01, 0x61, 0x0c, 0x72, 0x6f, 0x6f, 0x74, 0x2d, 0x73,
            0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x03, 0x6e, 0x65, 0x74, 0x00, 0x05, 0x6e, 0x73,
            0x74, 0x6c, 0x64, 0x0c, 0x76, 0x65, 0x72, 0x69, 0x73, 0x69, 0x67, 0x6e, 0x2d, 0x67,
            0x72, 0x73, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x78, 0x68, 0x7a, 0x68, 0x00, 0x00, 0x07,
            0x08, 0x00, 0x00, 0x03, 0x84, 0x00, 0x09, 0x3a, 0x80, 0x00, 0x01, 0x51, 0x80,
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
            0x07, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x04, 0x6c, 0x69, 0x76, 0x65, 0x03,
            0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
        ];

        let result = parse_question(&a);
        let question = Question{
            q_name: Some(DNSName{
                labels: vec![String::from("storage"), String::from("live"),String::from("com")]
            }),
            q_type: DNSType::A,
            q_class: DNSClass::IN,
        };
        assert_eq!(result.is_ok(), true);
        assert_eq!(result.unwrap().1, question );

    }
}
