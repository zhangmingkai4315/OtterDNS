mod server;

extern crate dnsproto;
use crate::server::Server;
use otterlib::errors::{OtterError, SettingError};
use otterlib::setting::Settings;

#[tokio::main]
async fn main() -> Result<(), OtterError> {
    match Settings::new("example.config.yaml") {
        Ok(setting) => {
            let mut server = Server::new(setting);
            server.run().await?
        }
        Err(err) => return Err(OtterError::SettingError(err)),
    };
    Ok(())
}
