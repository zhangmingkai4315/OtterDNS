#![allow(dead_code)]

/// fqdn return a fully qualified domain name.
fn fqdn(domain: &str) -> String{
    if is_fqdn(domain){
        return domain.to_owned();
    }
    return domain.to_owned() + ".";
}

fn is_fqdn(domain: &str) -> bool{
    let domain_str = domain.trim_end_matches('.');
    // abc == abc
    if domain == domain_str{
        return false;
    }
    true
}


static MAX_DOMAIN_LENGTH: usize= 255;


fn valid_domain(domain: &str) -> bool{
    let domain_str = fqdn(domain);
    if domain_str.len()>MAX_DOMAIN_LENGTH{
        return false
    }
    let domain_str = domain_str.trim_end_matches('.');
    if domain_str == ""{
        return true;
    }
    let labels = domain_str.split(".");

    for single_label in labels{
        if single_label.len() > 63 {
            return false;
        }
        if single_label.trim() == ""{
            return false;
        }
        // rfc1912:  llowable characters in a label for a host name are only ASCII letters, digits,
        // and the `-' character. Labels may not be all numbers,but may have a leading digit (e.g., 3com.com).
        // Labels must end and begin only with a letter or digit.
        if single_label.chars().all(|x| (x.is_ascii_alphanumeric() || x == '-')) == false{
            return false
        }
        if single_label.starts_with('-') == true || single_label.ends_with('-') == true{
            return false
        }
    }
    return true
}


#[cfg(test)]
mod test{
    use crate::dns::domain::{fqdn, valid_domain, is_fqdn};

    #[test]
    fn test_fqdn(){
        assert_eq!(fqdn("www.baidu.com"), "www.baidu.com.");
        assert_eq!(fqdn("www.baidu.com."), "www.baidu.com.");
        assert_eq!(fqdn("com"), "com.");
        assert_eq!(fqdn("com."), "com.");
        assert_eq!(fqdn(""), ".");
    }

    #[test]
    fn test_is_fqdn(){
        assert_eq!(is_fqdn("www.baidu.com"),false);
        assert_eq!(is_fqdn("www.baidu.com."),true);
        assert_eq!(is_fqdn("com"), false);
        assert_eq!(is_fqdn("com."), true);
        assert_eq!(is_fqdn(""), false);
    }

    #[test]
    fn test_valid_domain(){
        assert_eq!(valid_domain("www.baidu.com"), true);
        assert_eq!(valid_domain(""), true);
        assert_eq!(valid_domain("_.baidu.com"), false);
        assert_eq!(valid_domain("..com"), false);
        assert_eq!(valid_domain(".2.com"), false);
        assert_eq!(valid_domain("123.baidu.com"), true);
        let oversize_domain: String = vec!['a';256].into_iter().collect();
        assert_eq!(valid_domain(oversize_domain.as_str()), false);

        let oversize_label: String = vec!['a';64].into_iter().collect();
        assert_eq!(valid_domain((oversize_label + ".com").as_str()), false);
    }

}