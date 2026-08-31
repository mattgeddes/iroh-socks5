//! The local SOCKS5 proxy side of the SOCKS5-over-iroh protocol.
//!
//! A [`Client`] listens on a local TCP address, speaks the SOCKS5 protocol to
//! any client that connects, and forwards each session over a single
//! bidirectional iroh stream to a remote [`Server`] (`crate::server`), which
//! makes the actual outbound connection.

use std::net::{Ipv4Addr, SocketAddr};

use anyhow::{bail, Context, Result};
use iroh::endpoint::{Endpoint, RecvStream, SendStream};
use iroh::{EndpointAddr, EndpointId};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::protocol::{self, Reply, Request, TargetAddr};
use crate::relay;
use crate::socks5::{self, Socks5Request, CMD_BIND, CMD_CONNECT, CMD_UDP_ASSOCIATE};

/// A SOCKS5 proxy that forwards sessions to a remote iroh endpoint.
#[derive(Debug, Clone)]
pub struct Client {
    pub(crate) endpoint: Endpoint,
    pub(crate) remote: EndpointAddr,
}

impl Client {
    /// Create a client that forwards to the given remote endpoint address.
    pub fn new(endpoint: Endpoint, remote: impl Into<EndpointAddr>) -> Self {
        Self {
            endpoint,
            remote: remote.into(),
        }
    }

    /// The underlying iroh endpoint.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// This client's endpoint id.
    pub fn id(&self) -> EndpointId {
        self.endpoint.id()
    }

    /// Bind a local TCP listener for the SOCKS5 proxy.
    pub async fn bind_listener(&self, addr: SocketAddr) -> Result<TcpListener> {
        Ok(TcpListener::bind(addr).await?)
    }

    /// Serve SOCKS5 clients on `listener` forever.
    pub async fn serve(&self, listener: TcpListener) -> Result<()> {
        loop {
            let (tcp, peer) = listener.accept().await?;
            let client = self.clone();
            tokio::spawn(async move {
                if let Err(err) = client.handle_connection(tcp, peer).await {
                    tracing::debug!(%peer, "session ended with error: {err:#}");
                }
            });
        }
    }

    /// Bind a listener on `addr` and serve SOCKS5 clients on it.
    pub async fn run(&self, addr: SocketAddr) -> Result<()> {
        let listener = self.bind_listener(addr).await?;
        tracing::info!(local = %addr, remote = %self.remote.id, "SOCKS5 proxy listening");
        self.serve(listener).await
    }

    /// Handles a single SOCKS5 session on an accepted TCP connection.
    pub async fn handle_connection(&self, tcp: TcpStream, peer: SocketAddr) -> Result<()> {
        let mut tcp = tcp;
        socks5::negotiate(&mut tcp).await?;
        let request = socks5::read_request(&mut tcp).await?;
        match request.command {
            CMD_CONNECT | CMD_BIND | CMD_UDP_ASSOCIATE => {}
            _ => {
                socks5::write_reply(&mut tcp, socks5::REP_COMMAND_NOT_SUPPORTED, None).await?;
                return Ok(());
            }
        }
        self.forward(tcp, request, peer).await
    }

    async fn forward(
        &self,
        tcp: TcpStream,
        request: Socks5Request,
        peer: SocketAddr,
    ) -> Result<()> {
        let conn = self
            .endpoint
            .connect(self.remote.clone(), protocol::ALPN)
            .await
            .with_context(|| format!("failed to connect to remote endpoint {}", self.remote.id))?;
        let (mut send, mut recv) = conn.open_bi().await?;
        let result = match request.command {
            CMD_CONNECT => {
                let req = Request::Connect(request.target);
                protocol::write_frame(&mut send, &req).await?;
                handle_connect(tcp, &mut send, &mut recv).await
            }
            CMD_BIND => {
                let req = Request::Bind(request.target);
                protocol::write_frame(&mut send, &req).await?;
                handle_bind(tcp, &mut send, &mut recv).await
            }
            CMD_UDP_ASSOCIATE => {
                let req = Request::UdpAssociate(request.target);
                protocol::write_frame(&mut send, &req).await?;
                handle_udp(tcp, &mut send, &mut recv, req, peer).await
            }
            _ => bail!("unsupported command"),
        };
        conn.close(0u32.into(), b"socks session done");
        result
    }
}

async fn handle_connect(
    mut tcp: TcpStream,
    send: &mut SendStream,
    recv: &mut RecvStream,
) -> Result<()> {
    let reply: Reply = protocol::read_frame(recv)
        .await?
        .context("no reply from remote")?;
    socks5::write_reply(&mut tcp, reply.code, reply.addr).await?;
    if reply.code != socks5::REP_SUCCEEDED {
        return Ok(());
    }
    relay::relay_tcp(tcp, send, recv).await
}

async fn handle_bind(
    mut tcp: TcpStream,
    send: &mut SendStream,
    recv: &mut RecvStream,
) -> Result<()> {
    let reply: Reply = protocol::read_frame(recv)
        .await?
        .context("no reply from remote")?;
    socks5::write_reply(&mut tcp, reply.code, reply.addr).await?;
    if reply.code != socks5::REP_SUCCEEDED {
        return Ok(());
    }
    let reply: Reply = protocol::read_frame(recv)
        .await?
        .context("no second reply from remote")?;
    socks5::write_reply(&mut tcp, reply.code, reply.addr).await?;
    if reply.code != socks5::REP_SUCCEEDED {
        return Ok(());
    }
    relay::relay_tcp(tcp, send, recv).await
}

async fn handle_udp(
    mut tcp: TcpStream,
    send: &mut SendStream,
    recv: &mut RecvStream,
    req: Request,
    peer: SocketAddr,
) -> Result<()> {
    let Request::UdpAssociate(requested) = req else {
        bail!("expected UdpAssociate request");
    };
    let udp = bind_udp(&requested).await?;
    let local = udp.local_addr()?;
    let reply: Reply = protocol::read_frame(recv)
        .await?
        .context("no reply from remote")?;
    if reply.code != socks5::REP_SUCCEEDED {
        socks5::write_reply(&mut tcp, reply.code, reply.addr).await?;
        return Ok(());
    }
    socks5::write_reply(&mut tcp, socks5::REP_SUCCEEDED, Some(local)).await?;
    relay::relay_udp_client(udp, send, recv, &mut tcp, peer.ip()).await
}

/// Binds the local UDP socket the SOCKS5 client will send datagrams to.
async fn bind_udp(requested: &TargetAddr) -> Result<UdpSocket> {
    let addr = match requested {
        TargetAddr::Ip(addr) => *addr,
        TargetAddr::Domain(_, port) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, *port)),
    };
    match UdpSocket::bind(addr).await {
        Ok(udp) => Ok(udp),
        Err(_) if addr.ip().is_unspecified() => {
            anyhow::bail!("failed to bind {addr}")
        }
        Err(_) => {
            let fallback = SocketAddr::from((Ipv4Addr::UNSPECIFIED, addr.port()));
            UdpSocket::bind(fallback)
                .await
                .context("failed to bind UDP socket")
        }
    }
}
