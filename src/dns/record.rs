
/// https://tools.ietf.org/html/rfc1035#section-3.2.4
/// specify the class of the dns record data
#[derive(Debug)]
pub enum RecordClass{
    IN = 1,  // 1 the Internet
    CS,      // 2 the CSNET class
    CH,      // 3 the CHAOS class
    HS,      // 4 Hesiod
}

#[derive(Debug)]
pub enum DNSType{
    A = 1 ,
    NS = 2,
    CNAME = 5,
    SOA = 6,

    PTR = 12,
    HINFO = 13,
    MX = 15,
    TXT = 16,
    AAAA = 28,   // Rfc3596
    SRV = 33,
    DS = 43,
    RRSIG = 46,
    NSEC = 47,
    DNSKEY = 48,
    NSEC3 = 50,
    NSEC3PARAM = 51,
    AXFR = 252,
    Any = 255,  // Rfc1035: return all records of all types known to the dns server
}


#[derive(Debug)]
pub struct ResourceRecord{
    name: String,
    ttl: u32,
    r_class: RecordClass,
    r_type: DNSType,
    r_data: String,
}


