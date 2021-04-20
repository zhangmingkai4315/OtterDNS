use tokio::net::UdpSocket;

pub struct UdpServer {
    pub(crate) udp_socket: UdpSocket,
}

impl UdpServer {
    pub(crate) fn new(udp_socket: UdpSocket) -> UdpServer {
        UdpServer { udp_socket }
    }
}
