use crate::errors::NetworkError;
use std::net::SocketAddr;
use tokio::net::{TcpListener, UdpSocket};

pub struct Server {
    udp_listeners: Vec<UdpSocket>,
    tcp_listeners: Vec<TcpListener>,
}

impl Server {
    // bind addr must be string like: 127.0.0.1:53 192.168.0.1:53
    pub async fn new(tcp_addrs: Vec<&str>, udp_addrs: Vec<&str>) -> Result<Server, NetworkError> {
        let mut udp_listeners = vec![];
        let mut tcp_listeners = vec![];
        for tcp_addr in tcp_addrs.iter() {
            let tcp_addr = tcp_addr.parse::<SocketAddr>()?;
            let tcplistener = TcpListener::bind(tcp_addr).await?;
            tcp_listeners.push(tcplistener)
        }
        for udp_addr in udp_addrs.iter() {
            let udp_socket = udp_addr.parse::<SocketAddr>()?;
            let udpsocket = UdpSocket::bind(udp_socket).await?;
            udp_listeners.push(udpsocket)
        }
        Ok(Server {
            udp_listeners,
            tcp_listeners,
        })
    }
    pub fn run() {}
}

#[cfg(test)]
mod test {
    use crate::server::Server;

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn new_socket_server() {
        let new_servers = Server::new(vec!["127.0.0.1:15353"], vec!["127.0.0.1:15353"]).await;
        assert_eq!(new_servers.is_ok(), true);
        // new_servers.map_err(|err| println!("{:?}", err));
    }
}
