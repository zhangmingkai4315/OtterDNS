use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum SettingError {
    #[error("parse config file failed: {0}")]
    ParseConfigError(String),
    #[error("validation config setting failed: {0}")]
    ValidationError(String),
}
