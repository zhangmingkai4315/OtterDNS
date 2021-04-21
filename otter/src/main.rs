use clap::{App, Arg};
use otterlib::setting::Settings;
use server::Server;
use std::str::FromStr;
use tokio::runtime;
#[macro_use]
extern crate log;
use env_logger::Env;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

fn main() {
    let cpu_number = num_cpus::get().to_string();
    let matches = App::new("OtterDNS")
        .version(version())
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
        .arg(
            Arg::with_name("threads")
                .long("threads")
                .default_value(cpu_number.as_str())
                .validator(|v| match usize::from_str(v.as_str()) {
                    Ok(0..=256) => return Ok(()),
                    _ => Err(String::from(
                        "The threads value did not set correct [0, 256]",
                    )),
                })
                .help("threads number of dns server")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("loglevel")
                .long("log-level")
                .default_value("info")
                .validator(|v| match v.to_lowercase().as_str() {
                    "warn" | "error" | "info" | "debug" | "trace" => return Ok(()),
                    _ => Err(String::from("unknown log level")),
                })
                .help("set the level of log output")
                .takes_value(true),
        )
        .get_matches();
    let config_file = matches.value_of("config").unwrap();
    env_logger::Builder::from_env(
        Env::default().default_filter_or(matches.value_of("loglevel").unwrap()),
    )
    .init();
    match Settings::new(config_file) {
        Ok(setting) => {
            let mut server = Server::new(setting);
            info!("OtterDNS {} starting", version());
            let runtime = runtime::Builder::new_multi_thread()
                .enable_all()
                .worker_threads(usize::from_str(matches.value_of("threads").unwrap()).unwrap())
                .thread_name("otter-runtime")
                .build()
                .expect("failed to initialize dns server runtime");

            match runtime.block_on(server.run()) {
                Ok(()) => {
                    info!("OtterDNS {} stopping", version());
                }
                Err(err) => {
                    let error_msg =
                        format!("OtterDNS {} encountered a error: {:?}", version(), err);

                    error!("{}", error_msg);
                    panic!(error_msg)
                }
            }
        }
        Err(err) => error!("setting error: {:?}", err),
    };
}
