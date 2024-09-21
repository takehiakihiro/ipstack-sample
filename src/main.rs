use anyhow::Result;
use clap::Parser;
use etherparse::{IcmpEchoHeader, Icmpv4Header, IpNumber};
use ipstack::{stream::IpStackStream, IpStack, IpStackConfig};
use std::net::{IpAddr, SocketAddr};
use tokio::{
    io::{split, AsyncWriteExt},
    net::TcpStream,
};
use udp_stream::UdpStream;

const MTU: u16 = 1400;

#[repr(C)]
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum ArgVerbosity {
    Off = 0,
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

#[derive(Parser)]
#[command(author, version, about = "Testing app for tun.", long_about = None)]
struct Args {
    /// echo server address, likes `127.0.0.1:4000`
    #[arg(short, long, value_name = "IP:port", default_value = "127.0.0.1:4000")]
    vpn_addr: SocketAddr,

    /// echo server address, likes `127.0.0.1`
    #[arg(short, long, value_name = "IP address", default_value = "127.0.0.1")]
    server_addr: IpAddr,

    /// tcp timeout
    #[arg(long, value_name = "seconds", default_value = "10")]
    tcp_timeout: u64,

    /// udp timeout
    #[arg(long, value_name = "seconds", default_value = "10")]
    udp_timeout: u64,

    /// Verbosity level
    #[arg(short, long, value_name = "level", value_enum, default_value = "info")]
    pub verbosity: ArgVerbosity,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let default = format!("{:?}", args.verbosity);
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default)).init();

    let mut ipstack_config = IpStackConfig::default();
    ipstack_config.mtu = MTU;
    ipstack_config.tcp_timeout = std::time::Duration::from_secs(args.tcp_timeout);
    ipstack_config.udp_timeout = std::time::Duration::from_secs(args.udp_timeout);

    let mut vpn_stream = UdpStream::connect(args.vpn_addr).await?;
    let buf: [u8; 1] = [0];
    vpn_stream.write_all(&buf).await?;

    let mut ip_stack = IpStack::new(ipstack_config, vpn_stream);

    let server_addr = args.server_addr;

    let serial_number = std::sync::atomic::AtomicUsize::new(0);

    loop {
        let number = serial_number.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        match ip_stack.accept().await? {
            IpStackStream::Tcp(client_tcp) => {
                let local_addr = client_tcp.local_addr();
                let remote_addr = client_tcp.peer_addr();
                log::info!(
                    "TCP: client_addr({}) -> server_addr({})",
                    local_addr,
                    remote_addr
                );
                let connect_addr: SocketAddr =
                    format!("{}:{}", server_addr, remote_addr.port()).parse()?;
                let server_tcp = TcpStream::connect(connect_addr).await?;

                // ストリームを分割
                let (mut client_read, mut client_write) = split(client_tcp);
                let (mut server_read, mut server_write) = split(server_tcp);

                tokio::spawn(async move {
                    let client_to_server = async {
                        tokio::io::copy(&mut client_read, &mut server_write).await?;
                        server_write.shutdown().await
                    };

                    let server_to_client = async {
                        tokio::io::copy(&mut server_read, &mut client_write).await?;
                        client_write.shutdown().await
                    };

                    if let Err(e) = tokio::try_join!(client_to_server, server_to_client) {
                        log::error!("TCP proxy error: {:?}", e);
                    }
                });
            }

            IpStackStream::Udp(client_udp) => {
                let local_addr = client_udp.local_addr();
                let remote_addr = client_udp.peer_addr();
                log::info!(
                    "UDP: client_addr({}) -> server_addr({})",
                    local_addr,
                    remote_addr
                );
                let connect_addr: SocketAddr =
                    format!("{}:{}", server_addr, remote_addr.port()).parse()?;
                let server_udp = UdpStream::connect(connect_addr).await?;

                // ストリームを分割
                let (mut client_read, mut client_write) = split(client_udp);
                let (mut server_read, mut server_write) = split(server_udp);

                tokio::spawn(async move {
                    let client_to_server = async {
                        tokio::io::copy(&mut client_read, &mut server_write).await?;
                        server_write.shutdown().await
                    };

                    let server_to_client = async {
                        tokio::io::copy(&mut server_read, &mut client_write).await?;
                        client_write.shutdown().await
                    };

                    if let Err(e) = tokio::try_join!(client_to_server, server_to_client) {
                        log::error!("UDP proxy error: {:?}", e);
                    }
                });
            }

            IpStackStream::UnknownTransport(u) => {
                let n = number;
                if u.src_addr().is_ipv4() && IpNumber::from(u.ip_protocol()) == IpNumber::ICMP {
                    let (icmp_header, req_payload) = Icmpv4Header::from_slice(u.payload())?;
                    if let etherparse::Icmpv4Type::EchoRequest(req) = icmp_header.icmp_type {
                        log::info!("#{n} ICMPv4 echo");
                        let echo = IcmpEchoHeader {
                            id: req.id,
                            seq: req.seq,
                        };
                        let mut resp = Icmpv4Header::new(etherparse::Icmpv4Type::EchoReply(echo));
                        resp.update_checksum(req_payload);
                        let mut payload = resp.to_bytes().to_vec();
                        payload.extend_from_slice(req_payload);
                        u.send(payload)?;
                    } else {
                        log::info!("#{n} ICMPv4");
                    }
                    continue;
                }
                log::info!("#{n} unknown transport - Ip Protocol {:?}", u.ip_protocol());
                continue;
            }
            IpStackStream::UnknownNetwork(pkt) => {
                log::info!("#{number} unknown transport - {} bytes", pkt.len());
                continue;
            }
        };
    }
}
