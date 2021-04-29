use crate::tcp_server::TCPServer;
use crate::udp_server::UdpServer;
use dnsproto::dnsname::DNSName;
use dnsproto::message::Message;
use dnsproto::meta::{DNSType, RCode};
use net2::unix::UnixUdpBuilderExt;
// use net2::{TcpBuilder, UdpBuilder};
use otterlib::errors::OtterError;
use otterlib::errors::{DNSProtoErr, NetworkError, StorageError};
use otterlib::setting::{ExSetting, Settings};
use std::net::SocketAddr;
use std::result::Result::Err;
use std::sync::Arc;
use storage::storage::SafeRBTreeStorage;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;

pub type TokioError = Box<dyn std::error::Error + Send + Sync>;
pub type TokioResult<T> = std::result::Result<T, TokioError>;

/// report_query_message
fn report_query_message(dnsname: &DNSName, dnstype: &DNSType, remote: &SocketAddr, from_udp: bool) {
    info!(
        "receive query: {} IN {} from {} +{}",
        dnsname.to_string(),
        dnstype.to_string(),
        remote.to_string(),
        {
            if from_udp {
                "udp".to_string()
            } else {
                "tcp".to_string()
            }
        }
    )
}

/// process_message is the main dns process logic function
/// implements the rfc1034 and used for udp and tcp listeners
/// but not axfr and ixfr. if return err then just ignore the packet
fn process_message(
    mut storage: SafeRBTreeStorage,
    message: &[u8],
    remote: &SocketAddr,
    from_udp: bool,
    max_edns_size: u16,
) -> Result<Vec<u8>, DNSProtoErr> {
    let parsed_message = Message::parse_dns_message(&message)?;
    if !parsed_message.is_query() {
        // no need to process just drop packet
        return Err(DNSProtoErr::ValidQueryDomainErr);
    }

    let (dnsname, dnstype) = parsed_message.query_name_and_type()?;
    report_query_message(dnsname, dnstype, remote, from_udp);
    let (mut message, max_size, terminator) =
        Message::new_message_from_query(&parsed_message, from_udp, max_edns_size);
    if terminator {
        return message.encode(from_udp);
    }
    // 1. find the best zone for this query
    let best_zone = storage.find_best(dnsname);
    // 2. if not found
    //     2.1 because no subzone? then get the best zone name( using cut method )
    //     2.2 because not in this zone? then return refused status
    if best_zone.is_none() {
        message.header.set_rcode(RCode::Refused);
        return message.encode(from_udp);
    }
    // 3. find best zone for the qname (with wildcard, and zone cut info collection)
    // if query is a CNAME， we need do some loop job
    // 4. set dns header aa = true
    message.header.set_aa(true);
    // 5. get the zone reference
    let best_zone = best_zone.unwrap();
    // loop {}

    // 6. search current domain in best zone and trace the zonecut if exist!
    // 7. if zonecut exist :
    //      7.1 set dns header aa = false
    //      7.2 get the ns information put it to additional section
    // 8. if not exist
    //      8.1 then get the best zone's soa record
    //      8.2 get the ttl soa minimum
    //      8.3 set nxdomain
    // 9. find the node
    //      9.1 if CNAME exist then
    //          9.1.1 if qtype is CNAME then return a cname record
    //          9.1.2 if qtype is not CNAME then chase this query back to step 6:
    //          9.1.3 when chase the CNAME if not belong to this zone we do not chase again
    //          9.1.4 add any CNAME to the answer section
    //      9.2 if query type exist
    //          9.2.1 if query type is mx we also need to chase the mx record a/aaaa in the zone and
    //                add to additional
    //          9.2.2 add records to answer section
    //      9.3. if query type not exist
    //          9.3.1  find the soa record
    //          9.3.2  put the soa record to authority section
    // 10. add additional info

    match storage.search_rrset(dnsname, dnstype) {
        Ok(rrset) => {
            let rrset = rrset.read().unwrap().to_records();
            message.update_answer(rrset);
        }
        Err(err) => {
            match err {
                // add soa ?
                StorageError::DomainNotFoundError(_) => {
                    debug!(
                        "can't find record {} in zone database: {:?}",
                        dnsname.to_string(),
                        err,
                    );
                    message.set_nxdomain();
                }
                _ => {
                    debug!(
                        "can't find record {} in zone database: {:?}",
                        dnsname.to_string(),
                        err
                    );
                    message.set_serverfail();
                }
            }
        }
    }
    // debug!(logger, "response message: {:?}", message);
    let message_byte = message.encode(from_udp)?;
    // when query from udp and message size great than max_size(maybe limit by edns size)
    if from_udp && message_byte.len() > (max_size as usize) {
        let tc_message = Message::new_tc_message_from_build_message(&mut message);
        Ok(tc_message.encode(from_udp)?)
    } else {
        Ok(message_byte)
    }
}

pub struct OtterServer {
    udp_servers: Arc<Vec<UdpServer>>,
    tcp_servers: Arc<Vec<TCPServer>>,
    storage: SafeRBTreeStorage,
    setting: Settings,
    threads: Vec<JoinHandle<TokioResult<()>>>,
}

impl OtterServer {
    // bind addr must be string like: 127.0.0.1:53 192.168.0.1:53
    pub fn new(setting: Settings) -> OtterServer {
        // TODO: config file to logger
        OtterServer {
            udp_servers: Arc::new(vec![]),
            tcp_servers: Arc::new(vec![]),
            storage: SafeRBTreeStorage::default(),
            setting,
            threads: vec![],
        }
    }
    // setup after storage is ready
    pub async fn init_network(&mut self, extension: &ExSetting) -> Result<(), NetworkError> {
        let (tcp_listeners, udp_listeners) = self.setting.get_listeners();
        let mut tcp_servers = vec![];

        // for tcp_addr in tcp_listeners.iter() {
        //     info!("start listen tcp connection at: {}", tcp_addr);
        //     for _ in 0..extension.tcp_workers {
        //         let tcp_addr = tcp_addr.parse::<SocketAddr>()?;
        //         // let tcp_server = TcpListener::bind(tcp_addr).await?;
        //         // let tcp_socket = net2::TcpBuilder ::reuse_port(true).unwrap();
        //         let tcp_socket = if tcp_addr.is_ipv4() {
        //             net2::TcpBuilder::new_v4()
        //                 .unwrap()
        //                 .reuse_port(true)
        //                 .unwrap()
        //                 .bind(tcp_addr)
        //                 .unwrap()
        //                 .to_tcp_listener()
        //                 .unwrap()
        //         } else {
        //             net2::TcpBuilder::new_v6()
        //                 .unwrap()
        //                 .reuse_port(true)
        //                 .unwrap()
        //                 .bind(tcp_addr)
        //                 .unwrap()
        //                 .to_tcp_listener()
        //                 .unwrap()
        //         };
        //         let tcp_server = TcpListener::from_std(tcp_socket).unwrap();
        //         tcp_servers.push(TCPServer::new(tcp_server));
        //     }
        // }

        for tcp_addr in tcp_listeners.iter() {
            info!("start listen tcp connection at: {}", tcp_addr);
            // for _ in 0..extension.tcp_workers {
            let tcp_addr = tcp_addr.parse::<SocketAddr>()?;
            let tcp_server = TcpListener::bind(tcp_addr).await?;
            // let tcp_server = TcpListener::bind(tcp_addr).await?;
            // let tcp_socket = net2::TcpBuilder ::reuse_port(true).unwrap();
            // let tcp_socket = if tcp_addr.is_ipv4() {
            //     net2::TcpBuilder::new_v4()
            //         .unwrap()
            //         .reuse_port(true)
            //         .unwrap()
            //         .bind(tcp_addr)
            //         .unwrap()
            //         .to_tcp_listener()
            //         .unwrap()
            // } else {
            //     net2::TcpBuilder::new_v6()
            //         .unwrap()
            //         .reuse_port(true)
            //         .unwrap()
            //         .bind(tcp_addr)
            //         .unwrap()
            //         .to_tcp_listener()
            //         .unwrap()
            // };
            // let tcp_server = TcpListener::from_std(tcp_socket).unwrap();
            tcp_servers.push(TCPServer::new(tcp_server));
            // }
        }

        let mut udp_servers = vec![];

        for udp_addr in udp_listeners.iter() {
            info!("start listen udp connection at: {}", udp_addr);
            for _ in 0..extension.udp_workers {
                let udp_socket_addr = udp_addr.parse::<SocketAddr>()?;
                let udp_socket = if udp_socket_addr.is_ipv4() {
                    net2::UdpBuilder::new_v4()
                        .unwrap()
                        .reuse_port(true)
                        .unwrap()
                        .bind(udp_socket_addr)
                        .unwrap()
                } else {
                    net2::UdpBuilder::new_v6()
                        .unwrap()
                        .reuse_port(true)
                        .unwrap()
                        .bind(udp_socket_addr)
                        .unwrap()
                };
                let udp_socket = UdpSocket::from_std(udp_socket).unwrap();
                udp_servers.push(UdpServer::new(udp_socket));
            }
        }
        self.tcp_servers = Arc::new(tcp_servers);
        self.udp_servers = Arc::new(udp_servers);
        Ok(())
    }

    fn init_load_storage(&mut self) -> Result<(), OtterError> {
        let zone_file_list = self.setting.get_zone_file_list();
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
            self.storage.update_zone(file, orginal)?;
            info!("{}", format!("load zone file: {} success", file));
        }
        info!("load all zone files success");
        Ok(())
    }
    pub async fn run(&mut self, extension: &ExSetting) -> Result<(), OtterError> {
        self.init_load_storage()?;
        if let Err(err) = self.init_network(extension).await {
            return Err(OtterError::NetworkError(err));
        }
        let udp_server_number = self.udp_servers.len();
        let max_edns_size = self.setting.server.max_edns_size;
        for index in 0..udp_server_number {
            let storage = self.storage.clone();
            let servers_clone = self.udp_servers.clone();
            self.threads.push(tokio::spawn(async move {
                loop {
                    let storage = storage.clone();
                    let mut message = [0u8; 512];
                    match servers_clone[index]
                        .udp_socket
                        .recv_from(&mut message)
                        .await
                    {
                        Ok((vsize, connected_peer)) => {
                            let message = &message[0..vsize];
                            match process_message(
                                storage,
                                &message,
                                &connected_peer,
                                true,
                                max_edns_size,
                            ) {
                                Ok(message) => {
                                    if let Err(err) = servers_clone[index]
                                        .udp_socket
                                        .send_to(message.as_slice(), &connected_peer)
                                        .await
                                    {
                                        error!("send dns message back to client error: {}", err);
                                    }
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
            self.threads.push(tokio::spawn(async move {
                loop {
                    let storage = storage.clone();
                    if let Ok((mut stream, remote_addr)) =
                        servers_clone[index].tcp_listener.accept().await
                    {
                        let mut packet_length = [0u8; 2];
                        let next_size: u16;
                        if let Ok(v) = stream.read_exact(&mut packet_length).await {
                            if v != 2 {
                                continue;
                            }
                            next_size =
                                ((packet_length[0] as u16) << 8) + (packet_length[1] as u16);
                        } else {
                            continue;
                        }
                        let mut message: Vec<u8> = vec![0u8; next_size as usize];
                        match stream.read_exact(message.as_mut_slice()).await {
                            Ok(vsize) => {
                                let message = &message[0..vsize];
                                println!("{:?}", message);
                                match process_message(
                                    storage,
                                    &message,
                                    &remote_addr,
                                    false,
                                    max_edns_size,
                                ) {
                                    Ok(message) => {
                                        if let Err(err) = stream.write(message.as_slice()).await {
                                            error!("{:?}", err)
                                        };
                                        println!("{:?}", message);
                                        continue;
                                    }
                                    Err(err) => {
                                        error!("serialize message fail: {:?}", err);
                                        continue;
                                    }
                                }
                            }
                            Err(err) => {
                                error!("process message fail: {:?}", err);
                                continue;
                            }
                        };
                    };
                }
            }));
        }
        for join_handler in self.threads.iter_mut() {
            if let Err(err) = join_handler.await {
                error!("{:?}", err)
            };
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
        let extension = ExSetting {
            tcp_workers: 1,
            udp_workers: 1,
        };
        let mut servers = OtterServer::new(settings);
        let init_status = servers.init_network(&extension).await;
        assert_eq!(init_status.is_ok(), true);
        let init_status = servers.init_load_storage();
        // assert_eq!(init_status.is_ok(), true);
        if init_status.is_err() {
            println!("{:?}", init_status.unwrap_err())
        }
    }
}
