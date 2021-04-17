use dnsproto::dnsname::DNSName;
use dnsproto::message::Message;
use otterlib::errors::OtterError;
use otterlib::errors::{DNSProtoErr, NetworkError, StorageError};
use otterlib::setting::Settings;
use slog::{Drain, Logger};
use std::borrow::BorrowMut;
use std::net::SocketAddr;
use std::result::Result::Err;
use std::sync::{Arc, Mutex};
use storage::rb_storage;
use storage::rb_storage::RBTreeNode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;

pub type TokioError = Box<dyn std::error::Error + Send + Sync>;
pub type TokioResult<T> = std::result::Result<T, TokioError>;

pub struct UdpServer {
    udp_socket: UdpSocket,
}

fn process_message(
    storage: Arc<Mutex<RBTreeNode>>,
    message: &[u8],
    logger: &mut Logger,
) -> Result<Vec<u8>, DNSProtoErr> {
    let message = Message::parse_dns_message(&message)?;
    info!(logger, "{}", message.query_info());
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
    fn new(udp_socket: UdpSocket) -> UdpServer {
        UdpServer { udp_socket }
    }
}

impl TCPServer {
    fn new(tcp_listener: TcpListener) -> TCPServer {
        TCPServer { tcp_listener }
    }
}

pub struct TCPServer {
    tcp_listener: TcpListener,
}

pub struct Server {
    udp_servers: Arc<Vec<UdpServer>>,
    tcp_servers: Arc<Vec<TCPServer>>,
    storage: Arc<Mutex<RBTreeNode>>,
    setting: Settings,
    threads: Vec<JoinHandle<TokioResult<()>>>,
    server_logger: Logger,
    query_logger: Logger,
}

impl Server {
    // bind addr must be string like: 127.0.0.1:53 192.168.0.1:53
    pub fn new(setting: Settings) -> Server {
        // TODO: config file to logger
        let decorator = slog_term::TermDecorator::new().build();
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        let drain = slog_async::Async::new(drain).build().fuse();
        let logger = slog::Logger::root(drain, o!());
        let server_log = logger.new(o!("module" => "server"));
        let query_log = logger.new(o!("module" => "query"));
        Server {
            udp_servers: Arc::new(vec![]),
            tcp_servers: Arc::new(vec![]),
            storage: Arc::new(Mutex::new((RBTreeNode::new_root()))),
            setting,
            threads: vec![],
            server_logger: server_log,
            query_logger: query_log,
        }
    }
    // setup after storage is ready
    pub async fn init_network(&mut self) -> Result<(), NetworkError> {
        let (tcp_listeners, udp_listeners) = self.setting.get_listeners();
        let mut tcp_servers = vec![];
        for tcp_addr in tcp_listeners.iter() {
            let tcp_addr = tcp_addr.parse::<SocketAddr>()?;
            let tcp_server = TcpListener::bind(tcp_addr).await?;
            tcp_servers.push(TCPServer::new(tcp_server));
        }
        let mut udp_servers = vec![];
        for udp_addr in udp_listeners.iter() {
            let udp_socket_addr = udp_addr.parse::<SocketAddr>()?;
            let udp_socket = UdpSocket::bind(udp_socket_addr).await?;
            udp_servers.push(UdpServer::new(udp_socket));
        }
        self.tcp_servers = Arc::new(tcp_servers);
        self.udp_servers = Arc::new(udp_servers);
        Ok(())
    }

    fn init_load_storage(&mut self) -> Result<(), OtterError> {
        let zone_file_list = self.setting.get_zone_file_list();
        let mut storage = self.storage.lock().unwrap();
        let ref mut logger = self.server_logger.clone();
        for (file, domain) in &zone_file_list {
            let mut orginal: Option<String> = None;
            if !domain.is_empty() {
                match DNSName::new(domain, None) {
                    Ok(name) => {
                        orginal = Some(name.to_string());
                    }
                    Err(err) => {
                        return Err(OtterError::DNSProtoError(err));
                    }
                }
            }
            storage.update_zone(file, orginal)?;
            info!(logger, "{}", format!("load zone file: {} success", file));
        }
        info!(logger, "load all zone files success");
        Ok(())
    }
    pub async fn run(&mut self) -> Result<(), OtterError> {
        self.init_load_storage()?;
        if let Err(err) = self.init_network().await {
            return Err(OtterError::NetworkError(err));
        }
        let udp_server_number = self.udp_servers.len();

        for index in 0..udp_server_number {
            let storage = self.storage.clone();
            let servers_clone = self.udp_servers.clone();
            let mut query_logger = self.query_logger.clone();
            self.threads.push(tokio::spawn(async move {
                loop {
                    let mut message = [0u8; 4096];
                    match servers_clone[index].udp_socket.recv(&mut message).await {
                        Ok(vsize) => {
                            let message = &message[0..vsize];
                            match process_message(storage.clone(), &message, &mut query_logger) {
                                Ok(message) => {
                                    servers_clone[index]
                                        .udp_socket
                                        .send(message.as_slice())
                                        .await?;
                                    continue;
                                }
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
            }));
        }
        let tcp_server_number = self.tcp_servers.len();
        for index in 0..tcp_server_number {
            let storage = self.storage.clone();
            let servers_clone = self.tcp_servers.clone();
            let mut query_logger = self.query_logger.clone();
            self.threads.push(tokio::spawn(async move {
                loop {
                    if let Ok((mut stream, _)) = servers_clone[index].tcp_listener.accept().await {
                        let mut message: Vec<u8> = Vec::with_capacity(4096);
                        match stream.read(message.as_mut_slice()).await {
                            Ok(vsize) => {
                                let message = &message[0..vsize];
                                match process_message(storage.clone(), &message, &mut query_logger)
                                {
                                    Ok(message) => {
                                        stream.write(message.as_slice()).await;
                                        continue;
                                    }
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
                    };
                }
            }));
        }
        for join_handler in self.threads.iter_mut() {
            join_handler.await;
        }
        Ok(())
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
            file: "example.com.zone".to_string(),
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
