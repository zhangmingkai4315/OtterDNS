use config::{Config, ConfigError, File};
use validator::{Validate, ValidationError, ValidationErrors};

#[derive(Debug, Validate, Deserialize)]
struct Server {
    listen: String,
}

#[derive(Debug, Validate, Deserialize)]
struct Zone {
    domain: String,
    storage: String,
    file: String,
    master: Option<String>,
    acl: Option<Vec<String>>,
}

#[derive(Debug, Validate, Deserialize)]
struct Key {
    id: String,
    algorithm: String,
    secret: String,
}

#[derive(Debug, Validate, Deserialize)]
struct Log {
    target: String,
    #[validate(custom = "validate_log_level")]
    server: Option<String>,
    #[validate(custom = "validate_log_level")]
    query: Option<String>,
    #[validate(custom = "validate_log_level")]
    control: Option<String>,
}

#[derive(Debug, Validate, Deserialize)]
struct Remote {
    id: String,
    address: String,
    key: Option<String>,
}

#[derive(Debug, Validate, Deserialize)]
struct ACL {
    id: String,
    address: String,
    #[validate(custom = "validate_action")]
    action: String,
}

#[derive(Debug, Validate, Deserialize)]
pub struct Settings {
    server: Server,
    zone: Vec<Zone>,
    key: Vec<Key>,
    log: Vec<Log>,
    remote: Vec<Remote>,
    acl: Vec<ACL>,
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
