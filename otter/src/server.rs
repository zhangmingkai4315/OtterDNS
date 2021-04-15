use otterlib::errors::NetworkError;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use storage::rb_storage;

use otterlib::errors::OtterError;
use otterlib::setting::Settings;
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

    pub async fn init_socket(
        &mut self,
        tcp_addrs: Vec<&str>,
        udp_addrs: Vec<&str>,
    ) -> Result<(), NetworkError> {
        for tcp_addr in tcp_addrs.iter() {
            let tcp_addr = tcp_addr.parse::<SocketAddr>()?;
            let tcplistener = TcpListener::bind(tcp_addr).await?;
            self.tcp_listeners.push(tcplistener)
        }
        for udp_addr in udp_addrs.iter() {
            let udp_socket = udp_addr.parse::<SocketAddr>()?;
            let udpsocket = UdpSocket::bind(udp_socket).await?;
            self.udp_listeners.push(udpsocket)
        }
        Ok(())
    }

    fn init_load_storage(&mut self, file: &str) -> Result<(), OtterError> {
        let mut storage = self.storage.lock().unwrap();
        storage.update_zone(file, None)?;
        Ok(())
    }

    pub fn init(&mut self) {}
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn new_socket_server() {
        let mut settings = Settings::default();
        settings.server.listen = "0.0.0.0:15353";
        let new_servers = Server::new(settings);
        assert_eq!(new_servers.is_ok(), true);
        // new_servers.map_err(|err| println!("{:?}", err));
    }
}
