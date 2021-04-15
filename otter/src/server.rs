use dnsproto::dnsname::DNSName;
use otterlib::errors::NetworkError;
use otterlib::errors::OtterError;
use otterlib::setting::Settings;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use storage::rb_storage;
use storage::rb_storage::RBTreeNode;
use tokio::net::{TcpListener, UdpSocket};

pub struct Server {
    udp_listeners: Vec<UdpSocket>,
    tcp_listeners: Vec<TcpListener>,
    storage: Arc<Mutex<RBTreeNode>>,
    setting: Settings,
}

impl Server {
    // bind addr must be string like: 127.0.0.1:53 192.168.0.1:53
    pub fn new(setting: Settings) -> Server {
        Server {
            udp_listeners: vec![],
            tcp_listeners: vec![],
            storage: Arc::new(Mutex::new((RBTreeNode::new_root()))),
            setting,
        }
    }

    pub async fn init_network(&mut self) -> Result<(), NetworkError> {
        let (tcp_listeners, udp_listeners) = self.setting.get_listeners();
        for tcp_addr in tcp_listeners.iter() {
            let tcp_addr = tcp_addr.parse::<SocketAddr>()?;
            let tcplistener = TcpListener::bind(tcp_addr).await?;
            self.tcp_listeners.push(tcplistener)
        }
        for udp_addr in udp_listeners.iter() {
            let udp_socket = udp_addr.parse::<SocketAddr>()?;
            let udpsocket = UdpSocket::bind(udp_socket).await?;
            self.udp_listeners.push(udpsocket)
        }
        Ok(())
    }

    fn init_load_storage(&mut self) -> Result<(), OtterError> {
        let zone_file_list = self.setting.get_zone_file_list();
        let mut storage = self.storage.lock().unwrap();
        for (file, domain) in &zone_file_list {
            let mut orginal: Option<String> = None;
            if !domain.is_empty() {
                match DNSName::new(domain, None) {
                    Ok(name) => {
                        orginal = Some(name.to_string());
                    }
                    Err(err) => return Err(OtterError::DNSProtoError(err)),
                }
            }
            storage.update_zone(file, orginal)?;
        }

        Ok(())
    }

    pub fn init(&mut self) {}
}

#[cfg(test)]
mod test {
    use super::*;
    use otterlib::setting::ZoneSetting;

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn new_socket_server() {
        let mut settings = Settings::default();
        settings.server.listen = vec!["0.0.0.0:15353".to_string()];
        let zone = ZoneSetting {
            domain: "abc.com.".to_string(),
            file: "abc.com.zone".to_string(),
            master: None,
            notify: None,
            acl: None,
        };
        settings.zone.push(zone);
        let mut servers = Server::new(settings);
        let init_status = servers.init_network().await;
        assert_eq!(init_status.is_ok(), true);
        let init_status = servers.init_load_storage();
        // assert_eq!(init_status.is_ok(), true);
        if init_status.is_err() {
            println!("{:?}", init_status.unwrap_err())
        }
    }
}
