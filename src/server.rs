//! The remote proxy endpoint of the SOCKS5-over-iroh protocol.
//!
//! A [`Server`] listens on an iroh endpoint for the protocol's ALPN, checks
//! every connecting peer against an allow-list of [`EndpointId`]s, and then
//! makes the requested outbound connections on behalf of the caller.

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context, Result};
use iroh::endpoint::{Connection, Endpoint};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::EndpointId;
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::dns::DnsResolver;
use crate::protocol::{self, Reply, Request, TargetAddr};
use crate::relay;
use crate::socks5;

/// A SOCKS5-over-iroh server.
#[derive(Debug, Clone)]
pub struct Server {
    pub(crate) endpoint: Endpoint,
    pub(crate) router: Router,
}

impl Server {
    /// Build a server on `endpoint`, accepting only peers in `allow`.
    ///
    /// Domain targets are resolved with the operating system resolver; see
    /// [`Server::with_resolver`] to customize that.
    ///
    /// If `allow` is empty, connections from any peer are accepted and a
    /// warning is logged.
    pub async fn new(endpoint: Endpoint, allow: HashSet<EndpointId>) -> Result<Self> {
        Self::with_resolver(endpoint, allow, DnsResolver::system()).await
    }

    /// Build a server on `endpoint` like [`Server::new`], but resolve domain
    /// targets with `resolver` (e.g. a DNS-over-HTTPS resolver built with
    /// [`DnsResolver::from_url`]).
    pub async fn with_resolver(
        endpoint: Endpoint,
        allow: HashSet<EndpointId>,
        resolver: DnsResolver,
    ) -> Result<Self> {
        let handler = Handler::new(allow, resolver);
        let router = Router::builder(endpoint.clone())
            .accept(protocol::ALPN, handler)
            .spawn();
        Ok(Self { endpoint, router })
    }

    /// The underlying iroh endpoint.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// This server's endpoint id.
    pub fn id(&self) -> EndpointId {
        self.endpoint.id()
    }

    /// Shut the server down, closing the endpoint gracefully.
    pub async fn shutdown(self) -> Result<()> {
        self.router.shutdown().await.context("router shutdown")?;
        Ok(())
    }
}

/// The SOCKS5-over-iroh protocol handler, for mounting on a caller-managed [`Router`].
///
/// Use this instead of [`Server`] when the endpoint already has a router serving other
/// protocols: an endpoint can only have one router accepting its connections. Mount it under
/// [`crate::ALPN`].
#[derive(Debug, Clone)]
pub struct Handler {
    allow: Arc<HashSet<EndpointId>>,
    resolver: Arc<DnsResolver>,
}

impl Handler {
    /// Build a handler that accepts only peers in `allow` (or any peer, if `allow` is empty),
    /// resolving domain targets with `resolver`.
    pub fn new(allow: HashSet<EndpointId>, resolver: DnsResolver) -> Self {
        if allow.is_empty() {
            tracing::warn!("allow-list is empty; accepting connections from any endpoint");
        }
        Self {
            allow: Arc::new(allow),
            resolver: Arc::new(resolver),
        }
    }
}

impl ProtocolHandler for Handler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let remote = connection.remote_id();
        if !self.allow.is_empty() && !self.allow.contains(&remote) {
            tracing::warn!(%remote, "rejecting connection: endpoint not in allow-list");
            connection.close(0u32.into(), b"not allowed");
            return Ok(());
        }
        tracing::info!(%remote, "accepted connection");
        let resolver = self.resolver.clone();
        if let Err(err) = handle_connection(connection, resolver).await {
            tracing::warn!(%remote, "session ended with error: {err:#}");
        }
        Ok(())
    }
}

async fn handle_connection(connection: Connection, resolver: Arc<DnsResolver>) -> Result<()> {
    let (mut send, mut recv) = connection.accept_bi().await?;
    let request = match protocol::read_frame::<_, Request>(&mut recv).await? {
        Some(request) => request,
        None => {
            connection.closed().await;
            return Ok(());
        }
    };
    match request {
        Request::Connect(target) => {
            let (reply, tcp) = do_connect(&target, &resolver).await;
            protocol::write_frame(&mut send, &reply).await?;
            if let Some(tcp) = tcp {
                relay::relay_tcp(tcp, &mut send, &mut recv).await?;
            }
        }
        Request::Bind(target) => {
            let (reply, listener) = do_bind(&target).await;
            protocol::write_frame(&mut send, &reply).await?;
            if let Some(listener) = listener {
                match listener.accept().await {
                    Ok((tcp, peer)) => {
                        protocol::write_frame(&mut send, &Reply::ok(Some(peer))).await?;
                        relay::relay_tcp(tcp, &mut send, &mut recv).await?;
                    }
                    Err(e) => {
                        tracing::warn!("bind accept failed: {e}");
                        protocol::write_frame(
                            &mut send,
                            &Reply::fail(socks5::REP_CONNECTION_REFUSED),
                        )
                        .await?;
                    }
                }
            }
        }
        Request::UdpAssociate(target) => {
            let (reply, udp) = do_udp(&target).await;
            protocol::write_frame(&mut send, &reply).await?;
            if let Some(udp) = udp {
                relay::relay_udp_server(udp, &mut send, &mut recv, &resolver).await?;
            }
        }
    }
    connection.closed().await;
    Ok(())
}

async fn do_connect(target: &TargetAddr, resolver: &DnsResolver) -> (Reply, Option<TcpStream>) {
    let addr = match relay::resolve_target(resolver, target).await {
        Ok(addr) => addr,
        Err(e) => {
            tracing::debug!(target = %target, "failed to resolve target: {e:#}");
            return (Reply::fail(socks5::REP_HOST_UNREACHABLE), None);
        }
    };
    match TcpStream::connect(addr).await {
        Ok(tcp) => {
            let local = tcp.local_addr().ok();
            (Reply::ok(local), Some(tcp))
        }
        Err(e) => {
            let code = if e.kind() == std::io::ErrorKind::ConnectionRefused {
                socks5::REP_CONNECTION_REFUSED
            } else {
                socks5::REP_HOST_UNREACHABLE
            };
            tracing::debug!(%addr, "connect failed: {e}");
            (Reply::fail(code), None)
        }
    }
}

async fn do_bind(target: &TargetAddr) -> (Reply, Option<TcpListener>) {
    let addr = bind_addr(target);
    match TcpListener::bind(addr).await {
        Ok(listener) => (Reply::ok(listener.local_addr().ok()), Some(listener)),
        Err(e) => {
            tracing::debug!(%addr, "bind failed: {e}");
            (Reply::fail(socks5::REP_GENERAL_FAILURE), None)
        }
    }
}

async fn do_udp(target: &TargetAddr) -> (Reply, Option<UdpSocket>) {
    let addr = if matches!(target, TargetAddr::Ip(addr) if addr.is_ipv6()) {
        SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    };
    match UdpSocket::bind(addr).await {
        Ok(udp) => (Reply::ok(udp.local_addr().ok()), Some(udp)),
        Err(e) => {
            tracing::debug!(%addr, "udp bind failed: {e}");
            (Reply::fail(socks5::REP_GENERAL_FAILURE), None)
        }
    }
}

/// The socket address a request wants us to bind.
///
/// Domains are meaningless as bind addresses; the port is used with the
/// unspecified address.
fn bind_addr(target: &TargetAddr) -> SocketAddr {
    match target {
        TargetAddr::Ip(addr) => *addr,
        TargetAddr::Domain(_, port) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, *port)),
    }
}
