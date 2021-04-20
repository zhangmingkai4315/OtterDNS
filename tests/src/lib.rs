use otterlib::setting::{Settings, ZoneSetting};
use server::Server;

pub fn create_dns_server() -> Server {
    let mut settings = Settings::default();
    settings.server.listen = vec!["127.0.0.1:0".to_string()];
    let zone = ZoneSetting {
        domain: "abc.com.".to_string(),
        file: "example.com.zone".to_string(),
        master: None,
        notify: None,
        acl: None,
    };
    settings.zone.push(zone);
    let mut servers = Server::new(settings);
    servers
}
