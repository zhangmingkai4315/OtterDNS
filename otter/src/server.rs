use dnsproto::dnsname::DNSName;
use dnsproto::message::Message;
use otterlib::errors::OtterError;
use otterlib::errors::{DNSProtoErr, NetworkError, StorageError};
use otterlib::setting::Settings;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use storage::rb_storage;
use storage::rb_storage::RBTreeNode;
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;

pub struct UdpServer {
    storage: Arc<Mutex<RBTreeNode>>,
    udp_socket: UdpSocket,
}

impl UdpServer {
    fn new(storage: Arc<Mutex<RBTreeNode>>, udp_socket: UdpSocket) -> UdpServer {
        UdpServer {
            storage,
            udp_socket,
        }
    }

    fn process_message(storage: Arc<Mutex<RBTreeNode>>, message: &[u8]) -> Result<(), OtterError> {
        let message = Message::parse_dns_message(&message)?;
        let query_info = message.query_name_and_type()?;
        let mut storage = storage.lock().unwrap();
        let message = Message::new_message_from_query(&message);
        match storage.search_rrset(query_info.0, *query_info.1) {
            Ok(rrset) => {
                // TODO:
                message.set_answer(rrset)
            }
            Err(err) => {
                match err {
                    // add soa ?
                    StorageError::DomainNotFoundError(_) => message.set_nxdomain(),
                    _ => message.set_serverfail(),
                }
            }
        }
    }

    fn start(&self) -> JoinHandle<T> {
        tokio::task::spawn(move || {
            let mut message: Vec<u8> = Vec::with_capacity(4096);
            loop {
                let size = self.udp_socket.recv(&mut message).await;
                match size {
                    Ok(vsize) => {
                        let message = message[0..vsize];
                    }
                    Err(err) => continue,
                }
            }
        })
    }
}

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
    pub fn run(&mut self) {
        for listener in self.udp_listeners.iter() {
            listener.recv()
        }
        let join_handler = std::thread::spawn(|| {});
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
