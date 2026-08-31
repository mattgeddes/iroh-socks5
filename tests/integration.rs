#![cfg(feature = "test-utils")]

//! End-to-end integration tests for the SOCKS5-over-iroh protocol.
//!
//! These spin up a fully local iroh test infrastructure, a remote [`Server`],
//! a local [`Client`] proxy, and drive real SOCKS5 traffic through them over
//! loopback. No internet access is required.
//!
//! Run with: `cargo test --features test-utils`

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use iroh::{EndpointId, SecretKey};
use iroh_socks5::test_util::TestInfra;
use iroh_socks5::{Client, DnsResolver, Server};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use iroh_socks5::socks5::{
    CMD_BIND, CMD_CONNECT, CMD_UDP_ASSOCIATE, METHOD_NO_ACCEPTABLE, METHOD_NO_AUTH,
    REP_CONNECTION_REFUSED, REP_SUCCEEDED, VERSION,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(30);

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "debug".into()),
        )
        .try_init();
}

/// A running client proxy + remote server over a local test infrastructure.
struct Setup {
    #[allow(dead_code)]
    infra: TestInfra,
    #[allow(dead_code)]
    server: Server,
    #[allow(dead_code)]
    client: Client,
    proxy_addr: SocketAddr,
}

/// Starts a remote server (with the given allow-list) and a local SOCKS5 proxy
/// that forwards to it, returning the proxy's local address. The client dials
/// the server directly over loopback.
async fn setup(allow: Vec<EndpointId>) -> Result<Setup> {
    setup_with_client_key(SecretKey::generate(), allow, false).await
}

/// Like [`setup`], but the client dials the server through the shared relay.
async fn setup_via_relay(allow: Vec<EndpointId>) -> Result<Setup> {
    setup_with_client_key(SecretKey::generate(), allow, true).await
}

/// Like [`setup`], but with a caller-chosen client secret key (useful for
/// putting the client's own endpoint id on the server's allow-list).
async fn setup_with_client_key(
    client_key: SecretKey,
    allow: Vec<EndpointId>,
    via_relay: bool,
) -> Result<Setup> {
    init_tracing();
    let infra = TestInfra::new().await?;
    let server_ep = infra.endpoint(SecretKey::generate()).await?;
    let server = Server::new(server_ep.clone(), allow.into_iter().collect()).await?;
    // The server's endpoint must be reachable before the client dials.
    infra.wait_online(&server_ep).await?;

    let client_ep = infra.endpoint(client_key).await?;
    let remote = if via_relay {
        infra.remote_addr(server.id())
    } else {
        infra.direct_addr(&server_ep)
    };
    let client = Client::new(client_ep.clone(), remote);
    let listener = client
        .bind_listener(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await?;
    let proxy_addr = listener.local_addr()?;
    let serving = client.clone();
    tokio::spawn(async move {
        let _ = serving.serve(listener).await;
    });

    Ok(Setup {
        infra,
        server,
        client,
        proxy_addr,
    })
}

/// Like [`setup`], but the server resolves domain targets through `resolver`
/// instead of the operating system resolver.
async fn setup_with_resolver(allow: Vec<EndpointId>, resolver: DnsResolver) -> Result<Setup> {
    init_tracing();
    let infra = TestInfra::new().await?;
    let server_ep = infra.endpoint(SecretKey::generate()).await?;
    let server =
        Server::with_resolver(server_ep.clone(), allow.into_iter().collect(), resolver).await?;
    infra.wait_online(&server_ep).await?;

    let client_ep = infra.endpoint(SecretKey::generate()).await?;
    let remote = infra.direct_addr(&server_ep);
    let client = Client::new(client_ep.clone(), remote);
    let listener = client
        .bind_listener(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await?;
    let proxy_addr = listener.local_addr()?;
    let serving = client.clone();
    tokio::spawn(async move {
        let _ = serving.serve(listener).await;
    });

    Ok(Setup {
        infra,
        server,
        client,
        proxy_addr,
    })
}

/// Starts a local TCP echo server, returning its address.
async fn spawn_tcp_echo() -> Result<(TcpListener, SocketAddr)> {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
    let addr = listener.local_addr()?;
    Ok((listener, addr))
}

/// Sends the SOCKS5 greeting with a single method and returns the chosen method.
async fn greet(tcp: &mut TcpStream, methods: &[u8]) -> Result<u8> {
    tcp.write_all(&[VERSION, methods.len() as u8]).await?;
    tcp.write_all(methods).await?;
    let mut resp = [0u8; 2];
    tcp.read_exact(&mut resp).await?;
    Ok(resp[1])
}

/// Sends a SOCKS5 request with an IPv4 target.
async fn request_ipv4(tcp: &mut TcpStream, cmd: u8, target: SocketAddr) -> Result<()> {
    let ip = target.ip();
    assert!(ip.is_ipv4());
    let octets = match ip {
        std::net::IpAddr::V4(v4) => v4.octets(),
        _ => unreachable!(),
    };
    let mut buf = Vec::with_capacity(10);
    buf.extend_from_slice(&[VERSION, cmd, 0, 1]);
    buf.extend_from_slice(&octets);
    buf.extend_from_slice(&target.port().to_be_bytes());
    tcp.write_all(&buf).await?;
    Ok(())
}

/// Sends a SOCKS5 request with a domain target.
async fn request_domain(tcp: &mut TcpStream, cmd: u8, domain: &str, port: u16) -> Result<()> {
    let mut buf = Vec::with_capacity(7 + domain.len());
    buf.extend_from_slice(&[VERSION, cmd, 0, 3, domain.len() as u8]);
    buf.extend_from_slice(domain.as_bytes());
    buf.extend_from_slice(&port.to_be_bytes());
    tcp.write_all(&buf).await?;
    Ok(())
}

/// A parsed SOCKS5 reply.
#[derive(Debug)]
struct Reply {
    code: u8,
    bind: Option<SocketAddr>,
}

/// Reads a SOCKS5 reply.
async fn read_reply(tcp: &mut TcpStream) -> Result<Reply> {
    let mut hdr = [0u8; 4];
    tcp.read_exact(&mut hdr).await?;
    assert_eq!(hdr[0], VERSION, "bad reply version");
    assert_eq!(hdr[2], 0, "bad reply reserved byte");
    let bind = match hdr[3] {
        1 => {
            let mut b = [0u8; 6];
            tcp.read_exact(&mut b).await?;
            Some(SocketAddr::from((
                [b[0], b[1], b[2], b[3]],
                u16::from_be_bytes([b[4], b[5]]),
            )))
        }
        4 => {
            let mut b = [0u8; 18];
            tcp.read_exact(&mut b).await?;
            Some(SocketAddr::from((
                [
                    u16::from_be_bytes([b[0], b[1]]),
                    u16::from_be_bytes([b[2], b[3]]),
                    u16::from_be_bytes([b[4], b[5]]),
                    u16::from_be_bytes([b[6], b[7]]),
                    u16::from_be_bytes([b[8], b[9]]),
                    u16::from_be_bytes([b[10], b[11]]),
                    u16::from_be_bytes([b[12], b[13]]),
                    u16::from_be_bytes([b[14], b[15]]),
                ],
                u16::from_be_bytes([b[16], b[17]]),
            )))
        }
        3 => {
            let mut l = [0u8; 1];
            tcp.read_exact(&mut l).await?;
            let mut name = vec![0u8; l[0] as usize];
            tcp.read_exact(&mut name).await?;
            let mut port = [0u8; 2];
            tcp.read_exact(&mut port).await?;
            // Domain replies are never sent by our server; treat the reported
            // port on localhost as a stand-in.
            Some(SocketAddr::new(
                std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
                u16::from_be_bytes(port),
            ))
        }
        other => bail!("unexpected ATYP {other}"),
    };
    Ok(Reply { code: hdr[1], bind })
}

/// Full CONNECT handshake: greeting + request, returns the reply.
async fn connect_to(proxy: SocketAddr, target: SocketAddr) -> Result<(TcpStream, Reply)> {
    let mut tcp = TcpStream::connect(proxy).await?;
    assert_eq!(greet(&mut tcp, &[METHOD_NO_AUTH]).await?, METHOD_NO_AUTH);
    request_ipv4(&mut tcp, CMD_CONNECT, target).await?;
    let reply = read_reply(&mut tcp).await?;
    Ok((tcp, reply))
}

#[tokio::test]
async fn connect_tcp_echo_ipv4() -> Result<()> {
    let setup = setup(vec![]).await?;
    let (echo, echo_addr) = spawn_tcp_echo().await?;
    let echo_task = tokio::spawn(async move {
        let (mut s, _) = echo.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = s.read(&mut buf).await.unwrap();
        s.write_all(&buf[..n]).await.unwrap();
    });

    let (mut tcp, reply) = connect_to(setup.proxy_addr, echo_addr).await?;
    assert_eq!(reply.code, REP_SUCCEEDED);

    let payload = b"hello over iroh";
    tcp.write_all(payload).await?;
    let mut buf = vec![0u8; payload.len()];
    tokio::time::timeout(TEST_TIMEOUT, tcp.read_exact(&mut buf)).await??;
    assert_eq!(&buf, payload);
    echo_task.await?;
    Ok(())
}

#[tokio::test]
async fn connect_tcp_echo_via_relay() -> Result<()> {
    // Same as `connect_tcp_echo_ipv4`, but the client dials the server through
    // the shared relay instead of directly, exercising the alternate-relay
    // path.
    let setup = setup_via_relay(vec![]).await?;
    let (echo, echo_addr) = spawn_tcp_echo().await?;
    let echo_task = tokio::spawn(async move {
        let (mut s, _) = echo.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = s.read(&mut buf).await.unwrap();
        s.write_all(&buf[..n]).await.unwrap();
    });

    let (mut tcp, reply) = connect_to(setup.proxy_addr, echo_addr).await?;
    assert_eq!(reply.code, REP_SUCCEEDED);

    let payload = b"hello over the relay";
    tcp.write_all(payload).await?;
    let mut buf = vec![0u8; payload.len()];
    tokio::time::timeout(TEST_TIMEOUT, tcp.read_exact(&mut buf)).await??;
    assert_eq!(&buf, payload);
    echo_task.await?;
    Ok(())
}

#[tokio::test]
async fn connect_domain_resolution() -> Result<()> {
    let setup = setup(vec![]).await?;
    // Dual-stack listener so `localhost` (which may resolve to ::1 or
    // 127.0.0.1) can reach it either way.
    let listener = TcpListener::bind(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))).await?;
    let port = listener.local_addr()?.port();
    let echo_task = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = s.read(&mut buf).await.unwrap();
        s.write_all(&buf[..n]).await.unwrap();
    });

    let mut tcp = TcpStream::connect(setup.proxy_addr).await?;
    assert_eq!(greet(&mut tcp, &[METHOD_NO_AUTH]).await?, METHOD_NO_AUTH);
    request_domain(&mut tcp, CMD_CONNECT, "localhost", port).await?;
    let reply = read_reply(&mut tcp).await?;
    assert_eq!(reply.code, REP_SUCCEEDED);

    let payload = b"domain target works";
    tcp.write_all(payload).await?;
    let mut buf = vec![0u8; payload.len()];
    tokio::time::timeout(TEST_TIMEOUT, tcp.read_exact(&mut buf)).await??;
    assert_eq!(&buf, payload);
    echo_task.await?;
    Ok(())
}

#[tokio::test]
async fn connect_domain_resolved_via_doh() -> Result<()> {
    // A local DNS-over-HTTPS server maps every name to 127.0.0.1; `doh.example`
    // does not exist in the OS resolver, so a successful connect proves the
    // server-side DoH resolution was used.
    let doh = iroh_socks5::test_util::spawn_doh_server(Ipv4Addr::LOCALHOST.into()).await?;
    let setup = setup_with_resolver(vec![], doh.resolver()?).await?;

    let (echo, echo_addr) = spawn_tcp_echo().await?;
    let echo_task = tokio::spawn(async move {
        let (mut s, _) = echo.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = s.read(&mut buf).await.unwrap();
        s.write_all(&buf[..n]).await.unwrap();
    });

    let mut tcp = TcpStream::connect(setup.proxy_addr).await?;
    assert_eq!(greet(&mut tcp, &[METHOD_NO_AUTH]).await?, METHOD_NO_AUTH);
    request_domain(&mut tcp, CMD_CONNECT, "doh.example", echo_addr.port()).await?;
    let reply = read_reply(&mut tcp).await?;
    assert_eq!(reply.code, REP_SUCCEEDED);

    let payload = b"resolved over DNS-over-HTTPS";
    tcp.write_all(payload).await?;
    let mut buf = vec![0u8; payload.len()];
    tokio::time::timeout(TEST_TIMEOUT, tcp.read_exact(&mut buf)).await??;
    assert_eq!(&buf, payload);
    echo_task.await?;
    Ok(())
}

#[tokio::test]
async fn connect_refused_reports_error() -> Result<()> {
    let setup = setup(vec![]).await?;
    // A port nobody is listening on.
    let (listener, _) = spawn_tcp_echo().await?;
    let refused = SocketAddr::from((Ipv4Addr::LOCALHOST, listener.local_addr()?.port()));
    drop(listener); // free the port

    let (_tcp, reply) = connect_to(setup.proxy_addr, refused).await?;
    assert_eq!(reply.code, REP_CONNECTION_REFUSED);
    Ok(())
}

#[tokio::test]
async fn udp_associate_relay() -> Result<()> {
    let setup = setup(vec![]).await?;

    // A local UDP echo server.
    let echo = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
    let echo_addr = echo.local_addr()?;
    let echo_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        let (n, from) = echo.recv_from(&mut buf).await.unwrap();
        echo.send_to(&buf[..n], from).await.unwrap();
    });

    // Establish a UDP association through the proxy.
    let mut tcp = TcpStream::connect(setup.proxy_addr).await?;
    assert_eq!(greet(&mut tcp, &[METHOD_NO_AUTH]).await?, METHOD_NO_AUTH);
    request_ipv4(
        &mut tcp,
        CMD_UDP_ASSOCIATE,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    )
    .await?;
    let reply = read_reply(&mut tcp).await?;
    assert_eq!(reply.code, REP_SUCCEEDED);
    let proxy_udp = reply.bind.context("no relay address in reply")?;
    assert_eq!(proxy_udp.ip(), Ipv4Addr::LOCALHOST);

    // The application's datagram socket.
    let app = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;

    // Build a SOCKS5 UDP packet: RSV=0, FRAG=0, IPv4 target, payload.
    let payload = b"udp over iroh";
    let mut packet = vec![0u8, 0, 0, 1];
    let [a, b, c, d] = match echo_addr.ip() {
        std::net::IpAddr::V4(v4) => v4.octets(),
        _ => unreachable!(),
    };
    packet.extend_from_slice(&[a, b, c, d]);
    packet.extend_from_slice(&echo_addr.port().to_be_bytes());
    packet.extend_from_slice(payload);

    app.send_to(&packet, proxy_udp).await?;

    let mut buf = vec![0u8; 4096];
    let (n, from) = tokio::time::timeout(TEST_TIMEOUT, app.recv_from(&mut buf)).await??;
    assert_eq!(from, proxy_udp);
    // Parse the reply: RSV=0, FRAG=0, ATYP=1, addr, port, data.
    assert_eq!(buf[..4], [0, 0, 0, 1]);
    let port = u16::from_be_bytes([buf[8], buf[9]]);
    assert_eq!(
        SocketAddr::new(
            std::net::IpAddr::V4(Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7])),
            port
        ),
        echo_addr
    );
    assert_eq!(&buf[10..n], payload);
    echo_task.await?;
    Ok(())
}

#[tokio::test]
async fn bind_mode_relays_incoming() -> Result<()> {
    let setup = setup(vec![]).await?;

    // Control connection A.
    let mut a = TcpStream::connect(setup.proxy_addr).await?;
    assert_eq!(greet(&mut a, &[METHOD_NO_AUTH]).await?, METHOD_NO_AUTH);
    request_ipv4(&mut a, CMD_BIND, SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
    let first = read_reply(&mut a).await?;
    assert_eq!(first.code, REP_SUCCEEDED);
    let bound = first.bind.context("no bind address in reply")?;
    assert_eq!(bound.ip(), Ipv4Addr::LOCALHOST);

    // The "incoming" connection arrives at the remote's bound port.
    let mut b = TcpStream::connect(bound).await?;
    let second = read_reply(&mut a).await?;
    assert_eq!(second.code, REP_SUCCEEDED);

    let msg_a = b"from a";
    a.write_all(msg_a).await?;
    let mut buf = vec![0u8; msg_a.len()];
    tokio::time::timeout(TEST_TIMEOUT, b.read_exact(&mut buf)).await??;
    assert_eq!(&buf, msg_a);

    let msg_b = b"from b";
    b.write_all(msg_b).await?;
    let mut buf = vec![0u8; msg_b.len()];
    tokio::time::timeout(TEST_TIMEOUT, a.read_exact(&mut buf)).await??;
    assert_eq!(&buf, msg_b);
    Ok(())
}

#[tokio::test]
async fn allowlist_denies_unknown_peer() -> Result<()> {
    let allow = vec![SecretKey::generate().public()];
    let setup = setup(allow).await?;

    let mut tcp = TcpStream::connect(setup.proxy_addr).await?;
    assert_eq!(greet(&mut tcp, &[METHOD_NO_AUTH]).await?, METHOD_NO_AUTH);
    request_ipv4(
        &mut tcp,
        CMD_CONNECT,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
    )
    .await?;

    // The remote must refuse without a successful reply.
    let mut buf = [0u8; 4];
    let res = tokio::time::timeout(TEST_TIMEOUT, tcp.read(&mut buf)).await?;
    let n = res?;
    assert_eq!(n, 0, "expected the connection to be closed without a reply");
    Ok(())
}

#[tokio::test]
async fn allowlist_accepts_listed_peer() -> Result<()> {
    let client_key = SecretKey::generate();
    let allow = vec![client_key.public()];
    let setup = setup_with_client_key(client_key, allow, false).await?;

    let (echo, echo_addr) = spawn_tcp_echo().await?;
    let echo_task = tokio::spawn(async move {
        let (mut s, _) = echo.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = s.read(&mut buf).await.unwrap();
        s.write_all(&buf[..n]).await.unwrap();
    });
    let (mut tcp, reply) = connect_to(setup.proxy_addr, echo_addr).await?;
    assert_eq!(reply.code, REP_SUCCEEDED);
    tcp.write_all(b"ok").await?;
    let mut buf = [0u8; 2];
    tokio::time::timeout(TEST_TIMEOUT, tcp.read_exact(&mut buf)).await??;
    assert_eq!(&buf, b"ok");
    echo_task.await?;
    Ok(())
}

#[tokio::test]
async fn greeting_accepts_no_auth() -> Result<()> {
    let setup = setup(vec![]).await?;
    let mut tcp = TcpStream::connect(setup.proxy_addr).await?;
    assert_eq!(greet(&mut tcp, &[METHOD_NO_AUTH]).await?, METHOD_NO_AUTH);
    Ok(())
}

#[tokio::test]
async fn greeting_rejects_no_acceptable_method() -> Result<()> {
    let setup = setup(vec![]).await?;
    let mut tcp = TcpStream::connect(setup.proxy_addr).await?;
    assert_eq!(greet(&mut tcp, &[0x01]).await?, METHOD_NO_ACCEPTABLE);
    // The connection is then dropped by the proxy.
    let mut buf = [0u8; 4];
    let n = tcp.read(&mut buf).await?;
    assert_eq!(n, 0);
    Ok(())
}

#[tokio::test]
async fn unsupported_command_rejected() -> Result<()> {
    let setup = setup(vec![]).await?;
    let mut tcp = TcpStream::connect(setup.proxy_addr).await?;
    assert_eq!(greet(&mut tcp, &[METHOD_NO_AUTH]).await?, METHOD_NO_AUTH);
    request_ipv4(&mut tcp, 0x09, SocketAddr::from((Ipv4Addr::LOCALHOST, 1))).await?;
    let reply = read_reply(&mut tcp).await?;
    assert_eq!(reply.code, iroh_socks5::socks5::REP_COMMAND_NOT_SUPPORTED);
    Ok(())
}

#[tokio::test]
async fn bad_version_rejected() -> Result<()> {
    let setup = setup(vec![]).await?;
    let mut tcp = TcpStream::connect(setup.proxy_addr).await?;
    tcp.write_all(&[0x04, 0x01, 0x01, METHOD_NO_AUTH]).await?;
    // No reply is written; the connection is closed. Because the proxy never
    // read our bytes, the close may arrive as a RST rather than a FIN, so
    // either an EOF or a connection-reset error counts as success.
    let mut buf = [0u8; 4];
    let res = tokio::time::timeout(TEST_TIMEOUT, tcp.read(&mut buf)).await?;
    match res {
        Ok(n) => assert_eq!(n, 0, "expected the connection to be closed without a reply"),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        Err(e) => bail!("unexpected read error: {e}"),
    }
    Ok(())
}
