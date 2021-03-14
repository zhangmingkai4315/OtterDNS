#[macro_use]
extern crate serde;
extern crate config;

mod setting;

#[cfg(test)]
mod tests {
    use crate::setting::Settings;

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
}
