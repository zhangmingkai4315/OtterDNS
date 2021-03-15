use config::{Config, ConfigError, File};
use validator::{Validate, ValidationError, ValidationErrors};

#[derive(Debug, Validate, PartialEq, Deserialize)]
pub struct Server {
    pub listen: String,
}

#[derive(Debug, Validate, PartialEq, Deserialize)]
pub struct Zone {
    pub domain: String,
    pub storage: String,
    pub file: String,
    pub master: Option<String>,
    pub notify: Option<String>,
    pub acl: Option<Vec<String>>,
}

#[derive(Debug, Validate,PartialEq, Deserialize)]
pub struct Key {
    pub id: String,
    pub algorithm: String,
    pub secret: String,
}

#[derive(Debug, Validate, PartialEq, Deserialize)]
pub struct Log {
    pub target: String,
    #[validate(custom = "validate_log_level")]
    pub server: Option<String>,
    #[validate(custom = "validate_log_level")]
    pub query: Option<String>,
    #[validate(custom = "validate_log_level")]
    pub control: Option<String>,
}

#[derive(Debug, Validate, PartialEq, Deserialize)]
pub struct Remote {
    pub id: String,
    pub address: String,
    pub key: Option<String>,
}

#[derive(Debug, Validate, PartialEq, Deserialize)]
pub struct ACL {
    pub id: String,
    pub address: String,
    #[validate(custom = "validate_action")]
    pub action: String,
}

#[derive(Debug, Validate, PartialEq, Deserialize)]
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
    pub fn new(filename: &str) -> Result<Self, ConfigError> {
        let mut config_obj = Config::new();
        config_obj.merge(File::with_name(filename))?;
        config_obj.try_into()
    }
    #[allow(dead_code)]
    pub fn validation(&self) -> Result<(), ValidationErrors> {
        self.validate()
        // extension validate
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
