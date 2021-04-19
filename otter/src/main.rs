mod server;

#[macro_use]
extern crate slog;
extern crate slog_async;
extern crate slog_term;

extern crate dnsproto;
use crate::server::Server;
use clap::{App, Arg};
use otterlib::errors::OtterError;
use otterlib::setting::Settings;

#[tokio::main]
async fn main() -> Result<(), OtterError> {
    let matches = App::new("OtterDNS")
        .version("0.1.0")
        .author("mike zhang. <zhangmingkai.1989@gmail.com>")
        .about("a simple authority dns server")
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .default_value("config.yaml")
                .help("config file path")
                .takes_value(true),
        )
        .get_matches();
    let config_file = matches.value_of("config").unwrap();
    match Settings::new(config_file) {
        Ok(setting) => {
            let mut server = Server::new(setting);
            server.run().await?
        }
        Err(err) => return Err(OtterError::SettingError(err)),
    };

    Ok(())
}
