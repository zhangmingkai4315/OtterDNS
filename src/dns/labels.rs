#[derive(Debug, PartialEq)]
pub struct DNSName {
    pub(crate) labels: Vec<String>,
}

impl DNSName {
    pub fn new(raw: &[u8]) -> Option<DNSName> {
        let len = raw.len();
        if len == 0 || len > 256 {
            return None;
        }
        let mut shift: usize = 0;
        let mut labels = vec![];
        loop {
            if shift >= len{
                break;
            }
            let size = raw[shift] as usize;
            if size == 0 {
                break;
            }
            if (size + shift + 1) > len {
                return None;
            }
            let label = &raw[shift + 1..shift + 1 + size];
            match std::str::from_utf8(&label) {
                Ok(v) => labels.push(String::from(v)),
                _ => return None,
            }
            shift = shift + size + 1;
        }
        Some(DNSName { labels })
    }

    fn to_string(&self) -> String {
        let mut s = String::new();
        for label in &self.labels {
            s.push_str(label);
            s.push('.');
        }
        s
    }
}

#[cfg(test)]
mod label_test {
    use crate::dns::labels::DNSName;

    #[test]
    fn test_dns_name() {
        let raw = [
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        ];
        let dname = DNSName::new(&raw[..]);
        assert_eq!(dname.is_some(), true);
        let dname = dname.unwrap();
        assert_eq!(dname.labels.len(), 2);
        assert_eq!(dname.to_string(), String::from("google.com."));

        let raw = [
            0x10, 0x63, 0x74, 0x2d, 0x62, 0x6a, 0x73, 0x2d, 0x73, 0x67, 0x68, 0x2d, 0x30, 0x30,
            0x30, 0x30, 0x31, 0x0d, 0x6f, 0x6f, 0x73, 0x2d, 0x63, 0x6e, 0x2d, 0x31, 0x38, 0x30,
            0x36, 0x32, 0x32, 0x08, 0x63, 0x74, 0x79, 0x75, 0x6e, 0x61, 0x70, 0x69, 0x02, 0x63,
            0x6e, 0x00,
        ];
        let dname = DNSName::new(&raw[..]);
        assert_eq!(dname.is_some(), true);
        let dname = dname.unwrap();
        assert_eq!(dname.labels.len(), 4);
        assert_eq!(
            dname.to_string(),
            String::from("ct-bjs-sgh-00001.oos-cn-180622.ctyunapi.cn.")
        );

        let raw = [];
        let dname = DNSName::new(&raw);
        assert_eq!(dname.is_some(), false);

        let raw = [0x01];
        let dname = DNSName::new(&raw);
        assert_eq!(dname.is_some(), false);
    }
}
