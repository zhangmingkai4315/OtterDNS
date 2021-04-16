use dnsproto::dnsname::DNSName;
use dnsproto::message::Message;
use otterlib::errors::OtterError;
use otterlib::errors::{DNSProtoErr, NetworkError, StorageError};
use otterlib::setting::Settings;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use storage::rb_storage;
use storage::rb_storage::RBTreeNode;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;

pub struct UdpServer {
    storage: Arc<Mutex<RBTreeNode>>,
    udp_socket: UdpSocket,
}

fn process_message(
    storage: Arc<Mutex<RBTreeNode>>,
    message: &[u8],
) -> Result<Vec<u8>, DNSProtoErr> {
    let message = Message::parse_dns_message(&message)?;
    let query_info = message.query_name_and_type()?;
    let mut storage = storage.lock().unwrap();
    let mut message = Message::new_message_from_query(&message);
    match storage.search_rrset(query_info.0, *query_info.1) {
        Ok(rrset) => {
            // TODO:
            message.update_answer(rrset);
        }
        Err(err) => {
            match err {
                // add soa ?
                StorageError::DomainNotFoundError(_) => message.set_nxdomain(),
                _ => message.set_serverfail(),
            }
        }
    }
    message.encode()
}

impl UdpServer {
    fn new(storage: Arc<Mutex<RBTreeNode>>, udp_socket: UdpSocket) -> UdpServer {
        UdpServer {
            storage,
            udp_socket,
        }
    }

    fn start(&mut self) -> JoinHandle<_> {
        let storage = self.storage.clone();
        tokio::task::spawn(async move || {
            let mut message: Vec<u8> = Vec::with_capacity(4096);
            loop {
                let size = self.udp_socket.recv(&mut message).await;
                match size {
                    Ok(vsize) => {
                        let message = message[0..vsize];
                        match process_message(storage.clone(), &message) {
                            Ok(message) => self.udp_socket.send(message.as_slice()).await,
                            Err(err) => {
                                println!("serilize message fail: {:?}", err);
                                continue;
                            }
                        }
                    }
                    Err(err) => {
                        println!("process message fail: {:?}", err);
                        continue;
                    }
                }
            }
        })
    }
}

impl TCPServer {
    fn new(storage: Arc<Mutex<RBTreeNode>>, tcp_listener: TcpListener) -> TCPServer {
        TCPServer {
            storage,
            tcp_listener,
        }
    }

    fn start(&mut self) -> JoinHandle<_> {
        let storage = self.storage.clone();
        tokio::task::spawn(async move || loop {
            let (mut stream, _) = self.tcp_listener.accept().await?;
            let mut message: Vec<u8> = Vec::with_capacity(4096);
            match stream.read(message.as_mut_slice()).await {
                Ok(vsize) => {
                    let message = message[0..vsize];
                    match process_message(storage.clone(), &message) {
                        Ok(message) => self.udp_socket.send(message.as_slice()).await,
                        Err(err) => {
                            println!("serialize message fail: {:?}", err);
                            continue;
                        }
                    }
                }
                Err(err) => {
                    println!("process message fail: {:?}", err);
                    continue;
                }
            };
        })
    }
}

pub struct TCPServer {
    storage: Arc<Mutex<RBTreeNode>>,
    tcp_listener: TcpListener,
}

pub struct Server {
    udp_servers: Vec<UdpServer>,
    tcp_listeners: Vec<TCPServer>,
    storage: Arc<Mutex<RBTreeNode>>,
    setting: Settings,
    threads: Vec<JoinHandle<_>>,
}

impl Server {
    // bind addr must be string like: 127.0.0.1:53 192.168.0.1:53
    pub fn new(setting: Settings) -> Server {
        Server {
            udp_servers: vec![],
            tcp_listeners: vec![],
            storage: Arc::new(Mutex::new((RBTreeNode::new_root()))),
            setting,
            threads: vec![],
        }
    }
    // setup after storage is ready
    pub async fn init_network(&mut self) -> Result<(), NetworkError> {
        let (tcp_listeners, udp_listeners) = self.setting.get_listeners();
        for tcp_addr in tcp_listeners.iter() {
            let tcp_addr = tcp_addr.parse::<SocketAddr>()?;
            let tcplistener = TcpListener::bind(tcp_addr).await?;
            self.tcp_listeners
                .push(TCPServer::new(self.storage.clone(), tcplistener))
        }
        for udp_addr in udp_listeners.iter() {
            let udp_socket_addr = udp_addr.parse::<SocketAddr>()?;
            let udp_socket = UdpSocket::bind(udp_socket_addr).await?;
            self.udp_servers
                .push(UdpServer::new(self.storage.clone(), udp_socket));
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
    pub async fn run(&mut self) {
        self.init_load_storage();
        self.init_network().await?;

        for server in self.udp_servers.iter_mut() {
            let handler = server.start();
            self.threads.push(handler);
        }
        for server in self.tcp_listeners.iter_mut() {
            let handler = server.start();
            self.threads.push(handler);
        }
        for join_handler in self.threads {
            join_handler.await?;
        }
    }
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
