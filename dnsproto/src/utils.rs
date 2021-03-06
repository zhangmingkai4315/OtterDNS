use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

// fqdn return a fully qualified domain name.
pub fn fqdn(domain: &str) -> String {
    if is_fqdn(domain) {
        return domain.to_owned();
    }
    domain.to_owned() + "."
}

pub fn is_fqdn(domain: &str) -> bool {
    let domain_str = domain.trim_end_matches('.');
    // abc == abc
    if domain == domain_str {
        return false;
    }
    true
}

static MAX_DOMAIN_LENGTH: usize = 255;

pub fn valid_domain(domain: &str) -> bool {
    let domain_str = fqdn(domain);
    if domain_str.len() > MAX_DOMAIN_LENGTH {
        return false;
    }
    let domain_str = domain_str.trim_end_matches('.');
    if domain_str.is_empty() {
        return true;
    }
    let labels = domain_str.split('.');

    for single_label in labels {
        if single_label.len() > 63 {
            return false;
        }
        if single_label.trim() == "" {
            return false;
        }
        // rfc1912:  allowable characters in a label for a host name are only ASCII letters, digits,
        // and the `-' character. Labels may not be all numbers,but may have a leading digit (e.g., 3com.com).
        // Labels must end and begin only with a letter or digit.
        if !single_label
            .chars()
            .all(|x| (x.is_ascii_alphanumeric() || x == '-'))
        {
            return false;
        }
        if single_label.starts_with('-') || single_label.ends_with('-') {
            return false;
        }
    }
    true
}

pub fn is_safe_ascii(c_char: char, is_first: bool) -> bool {
    match c_char {
        check_c_char if !check_c_char.is_ascii() => false,
        check_c_char if check_c_char.is_alphanumeric() => true,
        '-' if !is_first => true, // dash is allowed
        '_' => true,              // SRV like labels
        '\\' => true,             // backslash
        '.' if !is_first => true, // must start with \
        '*' if is_first => true,  // wildcard
        _ => false,
    }
}

pub fn calculate_hash<T: Hash>(val: &T) -> u64 {
    let mut default_hash = DefaultHasher::new();
    val.hash(&mut default_hash);
    default_hash.finish()
}

#[cfg(test)]
mod utils {
    use super::*;
    #[test]
    fn test_fqdn() {
        assert_eq!(fqdn("www.baidu.com"), "www.baidu.com.");
        assert_eq!(fqdn("www.baidu.com."), "www.baidu.com.");
        assert_eq!(fqdn("com"), "com.");
        assert_eq!(fqdn("com."), "com.");
        assert_eq!(fqdn(""), ".");
    }

    #[test]
    fn test_is_fqdn() {
        assert_eq!(is_fqdn("www.baidu.com"), false);
        assert_eq!(is_fqdn("www.baidu.com."), true);
        assert_eq!(is_fqdn("com"), false);
        assert_eq!(is_fqdn("com."), true);
        assert_eq!(is_fqdn(""), false);
    }
    #[test]
    fn test_valid_domain() {
        assert_eq!(valid_domain("www.baidu.com"), true);
        assert_eq!(valid_domain(""), true);
        assert_eq!(valid_domain("_.baidu.com"), false);
        assert_eq!(valid_domain("..com"), false);
        assert_eq!(valid_domain(".2.com"), false);
        assert_eq!(valid_domain("123.baidu.com"), true);
        let oversize_domain: String = vec!['a'; 256].into_iter().collect();
        assert_eq!(valid_domain(oversize_domain.as_str()), false);

        let oversize_label: String = vec!['a'; 64].into_iter().collect();
        assert_eq!(valid_domain((oversize_label + ".com").as_str()), false);
    }
    #[test]
    fn test_is_safe_ascii() {
        assert_eq!(is_safe_ascii('a', true), true);
        assert_eq!(is_safe_ascii('a', false), true);
        assert_eq!(is_safe_ascii('1', true), true);
        assert_eq!(is_safe_ascii('1', false), true);
        assert_eq!(is_safe_ascii('-', false), true);
        assert_eq!(is_safe_ascii('*', true), true);
        assert_eq!(is_safe_ascii('_', true), true);
        assert_eq!(is_safe_ascii('_', false), true);
        assert_eq!(is_safe_ascii('%', false), false);
        assert_eq!(is_safe_ascii('=', false), false);
        assert_eq!(is_safe_ascii('-', true), false);
        assert_eq!(is_safe_ascii('*', false), false);
        assert_eq!(is_safe_ascii('\\', true), true);
        assert_eq!(is_safe_ascii('\\', false), true);
    }
}
