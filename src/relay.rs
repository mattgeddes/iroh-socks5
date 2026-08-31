//! Byte and datagram relay helpers shared by the client and server sides.

use std::net::{Ipv4Addr, SocketAddr};

use anyhow::{Context, Result};
use bytes::Bytes;
use iroh::endpoint::{RecvStream, SendStream};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};

use crate::dns::DnsResolver;
use crate::protocol::{self, Datagram, TargetAddr};
use crate::socks5;

/// Maximum size of a UDP datagram we will handle (the largest possible payload).
const MAX_UDP_DATAGRAM: usize = 65535;

/// Resolves a [`TargetAddr`] to a concrete [`SocketAddr`].
pub async fn resolve_target(resolver: &DnsResolver, target: &TargetAddr) -> Result<SocketAddr> {
    match target {
        TargetAddr::Ip(addr) => Ok(*addr),
        TargetAddr::Domain(domain, port) => {
            let addrs = resolver.resolve(domain, *port).await?;
            addrs
                .into_iter()
                .next()
                .context("no addresses found for domain")
        }
    }
}

/// Relays bytes in both directions between a TCP connection and an iroh
/// stream pair, propagating half-closes in both directions.
pub async fn relay_tcp(tcp: TcpStream, send: &mut SendStream, recv: &mut RecvStream) -> Result<()> {
    let (mut tcp_read, mut tcp_write) = tcp.into_split();
    let to_iroh = async {
        let res = tokio::io::copy(&mut tcp_read, &mut *send).await;
        // Signal end-of-stream to the remote peer.
        let _ = send.finish();
        res
    };
    let to_tcp = async {
        let res = tokio::io::copy(&mut *recv, &mut tcp_write).await;
        let _ = tcp_write.shutdown().await;
        res
    };
    let (a, b) = tokio::join!(to_iroh, to_tcp);
    a.context("relay tcp -> iroh")?;
    b.context("relay iroh -> tcp")?;
    Ok(())
}

/// Relays UDP datagrams for the local side of a SOCKS5 UDP association.
///
/// `tcp` is the SOCKS5 control connection; when it closes the association
/// ends. `peer_ip` is the IP of the associated TCP client; datagrams from any
/// other source are dropped. Replies from the remote proxy are delivered to
/// the most recent client source address.
pub async fn relay_udp_client(
    udp: UdpSocket,
    send: &mut SendStream,
    recv: &mut RecvStream,
    tcp: &mut TcpStream,
    peer_ip: std::net::IpAddr,
) -> Result<()> {
    let mut buf = vec![0u8; MAX_UDP_DATAGRAM];
    let mut app_src: Option<SocketAddr> = None;
    loop {
        tokio::select! {
            res = udp.recv_from(&mut buf) => {
                let (n, from) = res?;
                if from.ip() != peer_ip {
                    tracing::warn!(%from, "dropping UDP datagram from unexpected source");
                    continue;
                }
                let Some((frag, target, data)) = socks5::parse_udp_packet(&buf[..n]) else {
                    tracing::warn!("dropping malformed SOCKS5 UDP packet");
                    continue;
                };
                if frag != 0 {
                    tracing::warn!("dropping fragmented UDP packet (fragmentation not supported)");
                    continue;
                }
                app_src = Some(from);
                let dg = Datagram { addr: target, data: Bytes::copy_from_slice(data) };
                protocol::write_frame(&mut *send, &dg).await?;
            }
            res = protocol::read_frame::<_, Datagram>(&mut *recv) => {
                let Some(dg) = res? else { break };
                let Some(app_src) = app_src else { continue };
                let packet = socks5::format_udp_packet(&dg.addr, &dg.data);
                udp.send_to(&packet, app_src).await?;
            }
            res = wait_until_closed(tcp) => {
                res?;
                break;
            }
        }
    }
    Ok(())
}

/// Resolves once the SOCKS5 control connection has been closed by the client.
///
/// Any data still flowing on the control connection after the UDP association
/// is established is ignored; only an EOF (or an error) ends the association.
async fn wait_until_closed(tcp: &mut TcpStream) -> Result<()> {
    let mut buf = [0u8; 1];
    loop {
        tcp.readable().await?;
        match tcp.try_read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(_) => continue,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

/// Relays UDP datagrams for the remote side of a UDP association.
///
/// Datagrams received from the client are sent to their destination; replies
/// received from any destination are framed back to the client. Ends when the
/// client closes its half of the stream.
pub async fn relay_udp_server(
    udp: UdpSocket,
    send: &mut SendStream,
    recv: &mut RecvStream,
    resolver: &DnsResolver,
) -> Result<()> {
    let mut buf = vec![0u8; MAX_UDP_DATAGRAM];
    loop {
        tokio::select! {
            res = protocol::read_frame::<_, Datagram>(&mut *recv) => {
                let Some(dg) = res? else { break };
                match resolve_target(resolver, &dg.addr).await {
                    Ok(addr) => {
                        if let Err(e) = udp.send_to(&dg.data, addr).await {
                            tracing::warn!(%addr, "udp send failed: {e}");
                        }
                    }
                    Err(e) => tracing::warn!(target = %dg.addr, "failed to resolve target: {e:#}"),
                }
            }
            res = udp.recv_from(&mut buf) => {
                let (n, from) = res?;
                let dg = Datagram { addr: TargetAddr::Ip(from), data: Bytes::copy_from_slice(&buf[..n]) };
                if let Err(e) = protocol::write_frame(&mut *send, &dg).await {
                    tracing::debug!("udp relay stream closed: {e}");
                    break;
                }
            }
        }
    }
    Ok(())
}

/// The address used to bind a socket when the request gave no usable address.
pub fn default_bind_addr(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::UNSPECIFIED, port))
}
