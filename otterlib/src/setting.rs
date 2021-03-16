use crate::errors::SettingError;
use config::{Config, File};
use validator::{Validate, ValidationError, ValidationErrors};

#[derive(Debug, Clone, Validate, PartialEq, Deserialize)]
pub struct Server {
    pub listen: String,
}

#[derive(Debug, Clone, Validate, PartialEq, Deserialize)]
pub struct Zone {
    pub domain: String,
    pub storage: String,
    pub file: String,
    pub master: Option<String>,
    pub notify: Option<String>,
    pub acl: Option<Vec<String>>,
}

#[derive(Debug, Clone, Validate, PartialEq, Deserialize)]
pub struct Key {
    pub id: String,
    pub algorithm: String,
    pub secret: String,
}

#[derive(Debug, Clone, Validate, PartialEq, Deserialize)]
pub struct Log {
    pub target: String,
    #[validate(custom = "validate_log_level")]
    pub server: Option<String>,
    #[validate(custom = "validate_log_level")]
    pub query: Option<String>,
    #[validate(custom = "validate_log_level")]
    pub control: Option<String>,
}

#[derive(Debug, Clone, Validate, PartialEq, Deserialize)]
pub struct Remote {
    pub id: String,
    pub address: String,
    pub key: Option<String>,
}

#[derive(Debug, Clone, Validate, PartialEq, Deserialize)]
pub struct ACL {
    pub id: String,
    pub address: String,
    #[validate(custom = "validate_action")]
    pub action: String,
}

#[derive(Debug, Clone, Validate, PartialEq, Deserialize)]
pub struct Settings {
    pub server: Server,
    pub zone: Vec<Zone>,
    pub key: Vec<Key>,
    pub log: Vec<Log>,
    pub remote: Vec<Remote>,
    pub acl: Vec<ACL>,
}

impl Settings {
    #[allow(dead_code)]
    pub fn new(filename: &str) -> Result<Settings, SettingError> {
        let mut config_obj = Config::new();
        if let Err(err) = config_obj.merge(File::with_name(filename)) {
            return Err(SettingError::ParseConfigError(err.to_string()));
        }
        match config_obj.try_into::<Settings>() {
            Ok(v) => {
                if let Err(e) = v.validation() {
                    return Err(SettingError::ValidationError(e.to_string()));
                }
                Ok(v)
            }
            Err(err) => Err(SettingError::ParseConfigError(err.to_string())),
        }
    }
    #[allow(dead_code)]
    pub fn validation(&self) -> Result<(), ValidationErrors> {
        self.validate()
        // extension validate
    }

    // fn build_cache(&mut self) {
    //     for acl in self.acl.iter() {
    //         self.acl_cache.insert(acl.id.clone(), (*acl).clone());
    //     }
    //     for remote in self.remote.iter() {
    //         self.remote_cache
    //             .insert(remote.id.clone(), (*remote).clone());
    //     }
    //     for key in self.key.iter() {
    //         self.key_cache.insert(key.id.clone(), (*key).clone());
    //     }
    // }
    #[allow(dead_code)]
    pub fn get_acl_by_id(&self, id: &str) -> Option<ACL> {
        for acl in self.acl.iter() {
            if acl.id == id {
                return Some(acl.clone());
            }
        }
        None
    }
    #[allow(dead_code)]
    pub fn get_remote_by_id(&self, id: &str) -> Option<Remote> {
        for remote in self.remote.iter() {
            if remote.id == id {
                return Some(remote.clone());
            }
        }
        None
    }
    #[allow(dead_code)]
    pub fn get_key_by_id(&self, id: &str) -> Option<Key> {
        for key in self.key.iter() {
            if key.id == id {
                return Some(key.clone());
            }
        }
        None
    }
}

fn validate_action(action: &str) -> Result<(), ValidationError> {
    let action = action.to_lowercase();
    let desired_action = ["update", "notify", "transfer"];
    for i in desired_action.iter() {
        if action.eq(*i) {
            return Ok(());
        }
    }
    let error_message = format!("action validate fail: unknown action={}", action);
    Err(ValidationError::new(Box::leak(
        error_message.into_boxed_str(),
    )))
}

fn validate_log_level(level: &str) -> Result<(), ValidationError> {
    let level = level.to_lowercase();
    let desired_action = ["fatal", "error", "info", "warning", "debug", "trace", "off"];
    for i in desired_action.iter() {
        if level.eq(*i) {
            return Ok(());
        }
    }
    let error_message = format!("logging level validate fail: unknown level={}", level);
    Err(ValidationError::new(Box::leak(
        error_message.into_boxed_str(),
    )))
}
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
    assert_eq!(
        setting.zone[0].acl.as_ref().unwrap()[0],
        "notify_from_master"
    );

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

    assert_eq!(
        setting.key,
        vec![Key {
            id: "slave1_key".to_string(),
            algorithm: "hmac-md5".to_string(),
            secret: "Wg==".to_string()
        }]
    );
    assert_eq!(
        setting.log,
        vec![Log {
            target: "stdout".to_string(),
            server: Some("info".to_string()),
            query: Some("warning".to_string()),
            control: Some("debug".to_string()),
        }]
    );

    assert_eq!(
        setting.remote,
        vec![
            Remote {
                id: "master01".to_string(),
                address: "127.0.0.1".to_string(),
                key: None
            },
            Remote {
                id: "slave1".to_string(),
                address: "192.168.2.1@53".to_string(),
                key: Some("slave1_key".to_owned())
            }
        ]
    );

    assert_eq!(
        setting.acl,
        vec![
            ACL {
                id: "notify_from_master".to_string(),
                address: "192.168.1.1".to_string(),
                action: "notify".to_owned()
            },
            ACL {
                id: "slave1_acl".to_string(),
                address: "192.168.2.1".to_string(),
                action: "transfer".to_string()
            },
            ACL {
                id: "others_acl".to_string(),
                address: "192.168.3.0/24".to_string(),
                action: "transfer".to_string()
            },
            ACL {
                id: "update_acl".to_string(),
                address: "192.168.3.0/24".to_string(),
                action: "update".to_string()
            }
        ]
    );
}
#[test]
fn test_config_method() {
    let setting = Settings::new("example.config.yaml").unwrap();
    if let Some(v) = setting.get_acl_by_id("update_acl") {
        assert_eq!(
            v,
            ACL {
                id: "update_acl".to_string(),
                address: "192.168.3.0/24".to_string(),
                action: "update".to_string()
            }
        );
    } else {
        assert!(false, "should return update acl but got nothing")
    }

    if let Some(v) = setting.get_remote_by_id("master01") {
        assert_eq!(
            v,
            Remote {
                id: "master01".to_string(),
                address: "127.0.0.1".to_string(),
                key: None
            }
        );
    } else {
        assert!(false, "should return remote config but got nothing")
    }

    if let Some(v) = setting.get_key_by_id("slave1_key") {
        assert_eq!(
            v,
            Key {
                id: "slave1_key".to_string(),
                algorithm: "hmac-md5".to_string(),
                secret: "Wg==".to_string()
            }
        );
    } else {
        assert!(false, "should return key but got nothing")
    }
}
