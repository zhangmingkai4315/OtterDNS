#[macro_use]
extern crate serde;
extern crate config;

mod setting;

#[cfg(test)]
mod tests {
    use crate::setting::{Settings, Key, Log, Remote, ACL};

    #[test]
    fn test_read_config() {
        match Settings::new("example.config.yaml") {
            Ok(setting) => match setting.validation() {
                Ok(_) => {}
                Err(err) => assert!(
                    false,
                    format!("should validate success, but got: {}", err.to_string())
                ),
            },
            Err(err) => assert!(
                false,
                format!("should read success, but got: {}", err.to_string())
            ),
        }
    }
    #[test]
    fn test_config_attribute() {
        let setting = Settings::new("example.config.yaml").unwrap();
        assert_eq!(setting.server.listen, "0.0.0.0:53");
        assert_eq!(setting.zone[0].domain, "abc.com");
        assert_eq!(setting.zone[0].storage, "/abc/zones/");
        assert_eq!(setting.zone[0].file, "abc.com.zone");
        assert_eq!(setting.zone[0].master, Some("master01".to_owned()));
        assert_eq!(setting.zone[0].acl.as_ref().unwrap()[0], "notify_from_master");

        assert_eq!(setting.zone[1].domain, "com");
        assert_eq!(setting.zone[1].storage, "/abc/zones/");
        assert_eq!(setting.zone[1].file, "com.zone");
        assert_eq!(setting.zone[1].notify, Some("slave1".to_owned()));
        assert_eq!(setting.zone[1].acl.as_ref().unwrap()[0], "slave1_acl");
        assert_eq!(setting.zone[1].acl.as_ref().unwrap()[1], "others_acl");

        assert_eq!(setting.zone[2].domain, "example.com");
        assert_eq!(setting.zone[2].storage, "/abc/zones/");
        assert_eq!(setting.zone[2].file, "example.com.zone");
        assert_eq!(setting.zone[2].acl.as_ref().unwrap()[0], "update_acl");

        assert_eq!(setting.key, vec![Key{
            id: "slave1_key".to_string(),
            algorithm: "hmac-md5".to_string(),
            secret: "Wg==".to_string()
        }]);
        assert_eq!(setting.log, vec![Log{
            target: "stdout".to_string(),
            server: Some("info".to_string()),
            query: Some("warning".to_string()),
            control: Some("debug".to_string()),
        }]);

        assert_eq!(setting.remote, vec![Remote{
            id: "master01".to_string(),
            address: "127.0.0.1".to_string(),
            key: None
        },Remote{
            id: "slave1".to_string(),
            address: "192.168.2.1@53".to_string(),
            key: Some("slave1_key".to_owned())
        }]);

        assert_eq!(setting.acl, vec![ACL{
            id: "notify_from_master".to_string(),
            address: "192.168.1.1".to_string(),
            action: "notify".to_owned()
        },ACL{
            id: "slave1_acl".to_string(),
            address: "192.168.2.1".to_string(),
            action: "transfer".to_string()
        },ACL{
            id: "others_acl".to_string(),
            address: "192.168.3.0/24".to_string(),
            action: "transfer".to_string()
        },ACL{
            id: "update_acl".to_string(),
            address: "192.168.3.0/24".to_string(),
            action: "update".to_string()
        }]);
    }
}
