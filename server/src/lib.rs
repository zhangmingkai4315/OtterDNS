#[macro_use]
extern crate log;
pub use otter_server::OtterServer;
mod otter_server;
mod tcp_server;
mod udp_server;
