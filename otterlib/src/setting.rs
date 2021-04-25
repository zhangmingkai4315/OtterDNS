use crate::errors::SettingError;
use config::{Config, File};
use std::str::FromStr;
use validator::{Validate, ValidationError, ValidationErrors};

#[derive(Debug, Clone, Validate, PartialEq, Deserialize, Default)]
pub struct ExSetting {
    pub tcp_workers: usize,
    pub udp_workers: usize,
}

#[derive(Debug, Clone, Validate, PartialEq, Deserialize, Default)]
pub struct ServerSetting {
    pub listen: Vec<String>,
    pub max_edns_size: u16,
}

impl ServerSetting {
    fn validation(&self) -> Option<SettingError> {
        let (mut t_listeners, u_listeners) = self.get_listen_addr();
        t_listeners.extend_from_slice(u_listeners.as_slice());
        for t_listener in t_listeners {
            if let Err(err) = std::net::SocketAddr::from_str(t_listener.as_str()) {
                return Some(SettingError::ValidationServerConfigError(format!(
                    "{}",
                    err.to_string()
                )));
            }
        }
        if self.max_edns_size < 512 || self.max_edns_size > 4096 {
            return Some(SettingError::ValidationServerConfigError(
                "max-edns-size must set in range [512, 4096]".to_string(),
            ));
        }
        None
    }
    /// get_listen_addr will return tcplistener and udplistener in string vector.
    ///
    /// Return : (tcplistener: vec![String], udplistener:vec![String])
    ///
    fn get_listen_addr(&self) -> (Vec<String>, Vec<String>) {
        let mut tcplisteners = vec![];
        let mut udplisteners = vec![];
        for listen_addr in self.listen.iter() {
            let addr = listen_addr.trim().to_lowercase();
            if addr.ends_with("/tcp") {
                tcplisteners.push(addr[..addr.len() - 4].to_string());
            } else if addr.ends_with("/udp") {
                udplisteners.push(addr[..addr.len() - 4].to_string());
            } else {
                tcplisteners.push(addr.clone());
                udplisteners.push(addr);
            };
        }
        (tcplisteners, udplisteners)
    }
}

#[derive(Debug, Clone, Validate, PartialEq, Deserialize, Default)]
pub struct ZoneSetting {
    pub domain: String,
    pub file: String,
    pub master: Option<String>,
    pub notify: Option<String>,
    pub acl: Option<Vec<String>>,
}

#[derive(Debug, Clone, Validate, PartialEq, Deserialize, Default)]
pub struct KeySetting {
    pub id: String,
    pub algorithm: String,
    pub secret: String,
}

#[derive(Debug, Clone, Validate, PartialEq, Deserialize, Default)]
pub struct Log {
    pub target: String,
    #[validate(custom = "validate_log_level")]
    pub server: Option<String>,
    #[validate(custom = "validate_log_level")]
    pub query: Option<String>,
    #[validate(custom = "validate_log_level")]
    pub control: Option<String>,
}

#[derive(Debug, Clone, Validate, PartialEq, Deserialize, Default)]
pub struct Remote {
    pub id: String,
    pub address: String,
    pub key: Option<String>,
}

#[derive(Debug, Clone, Validate, PartialEq, Deserialize, Default)]
pub struct ACL {
    pub id: String,
    pub address: String,
    #[validate(custom = "validate_action")]
    pub action: String,
}

#[derive(Debug, Clone, Validate, PartialEq, Deserialize, Default)]
pub struct Settings {
    pub server: ServerSetting,
    pub zone: Vec<ZoneSetting>,
    pub key: Vec<KeySetting>,
    pub log: Vec<Log>,
    pub remote: Vec<Remote>,
    pub acl: Vec<ACL>,
}

impl Settings {
    #[allow(dead_code)]
    pub fn new(filename: &str) -> Result<Settings, SettingError> {
        let mut config_obj = Config::new();
        // set default value
        config_obj.set_default("server.max_edns_size", 1243)?;
        if let Err(err) = config_obj.merge(File::with_name(filename)) {
            return Err(SettingError::ParseConfigError(err.to_string()));
        }
        match config_obj.try_into::<Settings>() {
            Ok(setting) => {
                if let Err(e) = setting.validation() {
                    return Err(SettingError::ValidationError(e.to_string()));
                }
                Ok(setting)
            }
            Err(err) => Err(SettingError::ParseConfigError(err.to_string())),
        }
    }
    #[allow(dead_code)]
    pub fn validation(&self) -> Result<(), ValidationErrors> {
        self.validate()
        // extension validate
    }

    pub fn get_listeners(&self) -> (Vec<String>, Vec<String>) {
        self.server.get_listen_addr()
    }
    /// return (filepath, domain)
    pub fn get_zone_file_list(&self) -> Vec<(String, String)> {
        self.zone
            .iter()
            .map(|setting| (setting.file.clone(), setting.domain.clone()))
            .collect()
    }

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
    pub fn get_key_by_id(&self, id: &str) -> Option<KeySetting> {
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
#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_get_listen_addr() {
        let server = ServerSetting {
            listen: vec!["0.0.0.0:53".to_string(), "127.0.0.1:53/tcp".to_string()],
            max_edns_size: 1243,
        };
        assert_eq!(server.validation(), None);
        let (tcplisteners, udplisteners) = server.get_listen_addr();
        assert_eq!(
            tcplisteners,
            vec!["0.0.0.0:53".to_string(), "127.0.0.1:53".to_string()]
        );
        assert_eq!(udplisteners, vec!["0.0.0.0:53".to_string()]);
        let server = ServerSetting {
            listen: vec!["0.0.0.0:53".to_string(), "127.0.0.1:53/tcp".to_string()],
            max_edns_size: 100,
        };
        assert_eq!(server.validation().is_some(), true);
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
        assert_eq!(setting.server.listen, vec!["0.0.0.0:53".to_string()]);
        assert_eq!(setting.server.max_edns_size, 1024);
        assert_eq!(setting.zone[0].domain, "abc.com");
        assert_eq!(setting.zone[0].file, "example.com.zone");
        assert_eq!(setting.zone[0].master, Some("master01".to_owned()));
        assert_eq!(
            setting.zone[0].acl.as_ref().unwrap()[0],
            "notify_from_master"
        );

        assert_eq!(setting.zone[1].domain, "com");
        assert_eq!(setting.zone[1].file, "com.zone");
        assert_eq!(setting.zone[1].notify, Some("slave1".to_owned()));
        assert_eq!(setting.zone[1].acl.as_ref().unwrap()[0], "slave1_acl");
        assert_eq!(setting.zone[1].acl.as_ref().unwrap()[1], "others_acl");

        assert_eq!(setting.zone[2].domain, "example.com");
        assert_eq!(setting.zone[2].file, "example.com.zone");
        assert_eq!(setting.zone[2].acl.as_ref().unwrap()[0], "update_acl");

        assert_eq!(
            setting.key,
            vec![KeySetting {
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
                KeySetting {
                    id: "slave1_key".to_string(),
                    algorithm: "hmac-md5".to_string(),
                    secret: "Wg==".to_string()
                }
            );
        } else {
            assert!(false, "should return key but got nothing")
        }
    }
}
