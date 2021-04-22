#[macro_use]
extern crate log;
pub use server::OtterServer;
mod server;
mod tcp_server;
mod udp_server;
