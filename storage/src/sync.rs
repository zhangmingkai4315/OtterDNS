use crate::rb_storage::RBTreeNode;
use dnsproto::zone::{ZoneFileParser, ZoneReader};
use otterlib::errors::OtterError;

fn load_zone_from_disk(
    file: &str,
    default_origin: Option<String>,
) -> Result<RBTreeNode, OtterError> {
    let mut zone = RBTreeNode::new_root();
    let parser = ZoneFileParser::new(file)?;
    // read f
    let zone_reader = ZoneReader::new(parser, default_origin);
    for item in zone_reader {
        match item {
            Ok(rr) => {
                // insert rr record to zone node.
                zone.insert_rr(rr)?
            }
            Err(err) => eprintln!("{:?}", err),
        }
    }
    Ok(zone)
}

#[cfg(test)]
mod test {
    use crate::sync::load_zone_from_disk;
    use dnsproto::dnsname::DNSName;
    use dnsproto::meta::DNSType;

    #[test]
    fn test_load_zone_from_disk() {
        let search_items = [
            ("example.com.", DNSType::SOA, true),
            ("example.com.", DNSType::NS, true),
            ("example.com.", DNSType::MX, true),
            ("example.com.", DNSType::A, true),
            ("example.com.", DNSType::AAAA, true),
            ("ns.example.com.", DNSType::A, true),
            ("ns.example.com.", DNSType::AAAA, true),
            ("www.example.com.", DNSType::CNAME, true),
            ("wwwtest.example.com.", DNSType::CNAME, true),
            ("mail.example.com.", DNSType::A, true),
            ("main2.example.com.", DNSType::A, true),
            ("main3.example.com.", DNSType::A, true),
            // not exist type
            ("example.com.", DNSType::TXT, false),
            ("ns.example.com.", DNSType::TXT, false),
            ("www.example.com.", DNSType::TXT, false),
            ("wwwtest.example.com.", DNSType::TXT, false),
            ("mail.example.com.", DNSType::TXT, false),
            ("main2.example.com.", DNSType::TXT, false),
            ("main3.example.com.", DNSType::TXT, false),
            // not exist domain
            ("ns-noexist.example.com.", DNSType::AAAA, false),
            ("www-noexist.example.com.", DNSType::CNAME, false),
            ("wwwtest-noexist.example.com.", DNSType::CNAME, false),
            ("mail-noexist.example.com.", DNSType::A, false),
            ("main2-noexist.example.com.", DNSType::A, false),
            ("main3-noexist.example.com.", DNSType::A, false),
        ];
        let test_zone_file = "./test/example.zone";
        match load_zone_from_disk(test_zone_file, None) {
            Ok(mut zone) => {
                for item in search_items.iter() {
                    // zone.find()
                    match zone.search_rrset(&DNSName::new(item.0, None).unwrap(), item.1) {
                        Ok(rrset) => {
                            for rr in rrset.content() {
                                println!("{}", rr.to_string());
                            }
                            assert_eq!(
                                item.2,
                                true,
                                "domain: {} and type: {} should not exist but found",
                                item.0,
                                item.1.to_string(),
                            );
                        }
                        Err(_) => {
                            assert_eq!(
                                item.2,
                                false,
                                "domain: {} and type: {} should exist but not found",
                                item.0,
                                item.1.to_string(),
                            );
                        }
                    }
                }
            }
            Err(err) => {
                assert!(false, err.to_string())
            }
        }
    }
}
