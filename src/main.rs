use anyhow::Result;
use async_channel::unbounded;
use async_compat::CompatExt;
use bytes::Bytes;
use clap::Parser;
use etherparse::{IcmpEchoHeader, Icmpv4Header, IpNumber};
use ipstack_geph::stream::IpStackStream;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio::io::{split, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
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
    /// echo server address, likes `127.0.0.1`
    #[arg(short, long, value_name = "IP address")]
    server_addr: IpAddr,

    /// tcp timeout
    #[arg(long, value_name = "seconds", default_value = "60")]
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

    let ipv4 = Ipv4Addr::new(10, 0, 0, 33);
    let netmask = Ipv4Addr::new(255, 255, 255, 0);
    // let gateway = Ipv4Addr::new(10, 0, 0, 1);

    let mut tun_config = tun2::Configuration::default();
    tun_config.address(ipv4).netmask(netmask).mtu(MTU).up();

    tun_config.platform_config(|p_cfg| {
        p_cfg.ensure_root_privileges(true);
    });

    let mut ipstack_config = ipstack_geph::IpStackConfig::default();
    ipstack_config.mtu = MTU;
    ipstack_config.tcp_timeout = std::time::Duration::from_secs(args.tcp_timeout);
    ipstack_config.udp_timeout = std::time::Duration::from_secs(args.udp_timeout);

    // TUN デバイスの作成
    let tun = Arc::new(tun2::create_as_async(&tun_config)?);

    let (ipstack_input_tx, ipstack_input_rx) = unbounded::<Bytes>();
    let (ipstack_output_tx, ipstack_output_rx) = unbounded::<Bytes>();

    // TUN から読み取り、ipstack へ送信
    {
        let tun_clone = tun.clone();
        let ipstack_input_tx = ipstack_input_tx.clone();
        tokio::spawn(async move {
            let result: Result<(), anyhow::Error> = async {
                let mut buf = vec![0u8; MTU as usize];
                loop {
                    let n = tun_clone.recv(&mut buf).await?;
                    ipstack_input_tx
                        .send(Bytes::copy_from_slice(&buf[..n]))
                        .await?;
                }
            }
            .await;

            if let Err(e) = result {
                log::error!("Error in TUN reader task: {:?}", e);
            }
        });
    }

    // ipstack から読み取り、TUN へ書き込み
    {
        let tun_clone = tun.clone();
        let ipstack_output_rx = ipstack_output_rx.clone();
        tokio::spawn(async move {
            let result: Result<(), anyhow::Error> = async {
                while let Ok(bytes) = ipstack_output_rx.recv().await {
                    tun_clone.send(&bytes).await?;
                }
                Ok(())
            }
            .await;

            if let Err(e) = result {
                log::error!("Error in TUN writer task: {:?}", e);
            }
        });
    }

    let ip_stack = ipstack_geph::IpStack::new(ipstack_config, ipstack_input_rx, ipstack_output_tx);

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
                let client_tcp = client_tcp.compat();

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
                let mut server_udp = UdpStream::connect(connect_addr).await?;

                tokio::spawn(async move {
                    let mut server_buf = vec![0u8; 4096];

                    loop {
                        tokio::select! {
                            result = client_udp.recv() => {
                                match result {
                                    Ok(client_buf) => {
                                        if client_buf.len() == 0 {
                                            // クライアントからの接続が終了
                                            break;
                                        }
                                        if let Err(e) = server_udp.write(&client_buf).await {
                                            log::error!("Error sending to server_udp: {:?}", e);
                                            break;
                                        }
                                    }
                                    Err(e) => {
                                        log::error!("Error receiving from client_udp: {:?}", e);
                                        break;
                                    }
                                }
                            }
                            result = server_udp.read(&mut server_buf) => {
                                match result {
                                    Ok(n) => {
                                        if n == 0 {
                                            // サーバーからの接続が終了
                                            break;
                                        }
                                        if let Err(e) = client_udp.send(&server_buf[..n]).await {
                                            log::error!("Error sending to client_udp: {:?}", e);
                                            break;
                                        }
                                    }
                                    Err(e) => {
                                        log::error!("Error receiving from server_udp: {:?}", e);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                });
            }

            IpStackStream::UnknownTransport(u) => {
                let n = number;
                if u.src_addr().is_ipv4() && u.ip_protocol() == IpNumber::ICMP {
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
