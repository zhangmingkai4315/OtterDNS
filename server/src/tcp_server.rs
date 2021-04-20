use tokio::net::TcpListener;

pub struct TCPServer {
    pub(crate) tcp_listener: TcpListener,
}

impl TCPServer {
    pub(crate) fn new(tcp_listener: TcpListener) -> TCPServer {
        TCPServer { tcp_listener }
    }
}
