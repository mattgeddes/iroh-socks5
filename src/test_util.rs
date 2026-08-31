//! Test helpers for integration tests.
//!
//! Only available with the `test-utils` feature, which pulls in iroh's own test
//! infrastructure (a local relay server). This lets the integration tests
//! exercise the full client/server protocol over a real iroh connection
//! without relying on the public n0 infrastructure or on an internet
//! connection. Endpoints can dial each other either directly over loopback
//! ([`TestInfra::direct_addr`], the fast and deterministic choice) or through
//! the shared relay ([`TestInfra::remote_addr`]).
//!
//! # Usage
//!
//! ```no_run
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let infra = iroh_socks5::test_util::TestInfra::new().await?;
//!     let server_ep = infra.endpoint(iroh::SecretKey::generate()).await?; // the remote side
//!     let client_ep = infra.endpoint(iroh::SecretKey::generate()).await?; // the local side
//!     // Have the client dial the server directly over loopback:
//!     let remote = infra.direct_addr(&server_ep);
//!     client_ep.connect(remote, iroh_socks5::ALPN).await?;
//!     Ok(())
//! }
//! ```

use std::any::Any;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result};
use iroh::endpoint::RelayMode;
use iroh::test_utils::run_relay_server;
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMap, RelayUrl, SecretKey, TransportAddr};
use iroh_relay::tls::CaTlsConfig;

/// A fully local iroh test infrastructure.
///
/// Owns a relay server. Dropping this shuts it down. All endpoints created
/// from it share the same relay; see [`TestInfra::direct_addr`] and
/// [`TestInfra::remote_addr`] for the two ways to dial a peer.
#[derive(Debug)]
pub struct TestInfra {
    /// The relay map shared by all endpoints, including its QUIC address.
    pub relay_map: RelayMap,
    /// The relay URL shared by all endpoints.
    pub relay_url: RelayUrl,
    /// Keeps the relay server running; the actual server type is not public.
    _relay: Box<dyn Any + Send + Sync>,
}

impl TestInfra {
    /// Run the infrastructure.
    pub async fn new() -> Result<Self> {
        let (relay_map, relay_url, relay) =
            run_relay_server().await.context("run test relay server")?;
        Ok(Self {
            relay_map,
            relay_url,
            _relay: Box::new(relay),
        })
    }

    /// Build an iroh endpoint configured to use this infrastructure.
    pub fn endpoint_builder(&self, secret_key: SecretKey) -> iroh::endpoint::Builder {
        Endpoint::builder(iroh::endpoint::presets::Minimal)
            .secret_key(secret_key)
            .alpns(vec![crate::ALPN.to_vec()])
            .ca_tls_config(CaTlsConfig::insecure_skip_verify())
            .relay_mode(RelayMode::Custom(self.relay_map.clone()))
    }

    /// Bind a new endpoint on this infrastructure.
    pub async fn endpoint(&self, secret_key: SecretKey) -> Result<Endpoint> {
        self.endpoint_builder(secret_key)
            .bind()
            .await
            .context("bind test endpoint")
    }

    /// An [`EndpointAddr`] addressing `id` through the shared relay, for use
    /// with `Endpoint::connect`.
    pub fn remote_addr(&self, id: EndpointId) -> EndpointAddr {
        EndpointAddr {
            id,
            addrs: [TransportAddr::Relay(self.relay_url.clone())].into(),
        }
    }

    /// An [`EndpointAddr`] addressing `id` at loopback addresses, for use with
    /// `Endpoint::connect`. The endpoint binds wildcard addresses (e.g.
    /// `0.0.0.0:port`), which are not dialable, so the ports are re-addressed
    /// on loopback instead.
    pub fn direct_addr(&self, endpoint: &Endpoint) -> EndpointAddr {
        let mut addrs: BTreeSet<TransportAddr> = BTreeSet::new();
        for socket in endpoint.bound_sockets() {
            let loopback = match socket.ip() {
                IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
            };
            addrs.insert(TransportAddr::Ip(SocketAddr::new(loopback, socket.port())));
        }
        EndpointAddr {
            id: endpoint.id(),
            addrs,
        }
    }

    /// Wait until the endpoint is connected to its relay, so it is reachable
    /// by other endpoints on the same relay.
    pub async fn wait_online(&self, endpoint: &Endpoint) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(30), endpoint.online())
            .await
            .context("endpoint did not come online")?;
        Ok(())
    }
}

/// A minimal local DNS-over-HTTPS server for tests.
///
/// Serves an HTTP/2 endpoint (TLS, self-signed certificate for the
/// [`DohServer::sni`] name) on a loopback port and answers A/AAAA queries
/// with a canned address. Only available with the `dns-over-https` feature.
#[cfg(feature = "dns-over-https")]
pub struct DohServer {
    addr: SocketAddr,
    sni: &'static str,
    root_cert: rustls::pki_types::CertificateDer<'static>,
}

/// The server name the test DoH server's certificate is valid for.
#[cfg(feature = "dns-over-https")]
const DOH_SNI: &str = "doh.test";

#[cfg(feature = "dns-over-https")]
impl DohServer {
    /// The TLS address of the DoH server.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The server name (SNI) the certificate is valid for.
    pub fn sni(&self) -> &str {
        self.sni
    }

    /// A [`DnsResolver`](crate::DnsResolver) that resolves through this DoH
    /// server, trusting its self-signed certificate.
    pub fn resolver(&self) -> Result<crate::DnsResolver> {
        use hickory_resolver::config::ResolverConfig;
        use hickory_resolver::net::runtime::TokioRuntimeProvider;
        use hickory_resolver::TokioResolver;
        use rustls::RootCertStore;

        // hickory's public API fixes the DoH port at 443; a custom port (as
        // used here) is configured through its serde representation.
        let config: ResolverConfig = serde_json::from_value(serde_json::json!({
            "name_servers": [{
                "ip": self.addr.ip().to_string(),
                "connections": [{
                    "port": self.addr.port(),
                    "protocol": {
                        "type": "https",
                        "server_name": self.sni,
                        "path": "/dns-query",
                    },
                }],
            }],
        }))?;

        let mut roots = RootCertStore::empty();
        roots.add(self.root_cert.clone())?;
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        let resolver = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
            .with_tls_config(tls_config)
            .build()?;
        Ok(crate::DnsResolver::DoH(Box::new(resolver)))
    }
}

/// Spawn a local DNS-over-HTTPS server that answers every A/AAAA query with
/// `answer`, returning a handle to it.
#[cfg(feature = "dns-over-https")]
pub async fn spawn_doh_server(answer: std::net::IpAddr) -> Result<DohServer> {
    use std::sync::Arc;

    let sni = DOH_SNI;
    let key_pair = rcgen::KeyPair::generate().context("generate DoH key pair")?;
    let params =
        rcgen::CertificateParams::new(vec![sni.to_string()]).context("certificate params")?;
    let cert = params
        .self_signed(&key_pair)
        .context("self-sign certificate")?;

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                key_pair.serialize_der(),
            )),
        )
        .context("build TLS server config")?;
    tls_config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));

    let listener =
        tokio::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
    let addr = listener.local_addr()?;

    tokio::spawn(async move {
        loop {
            let Ok((tcp, _peer)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Err(err) = serve_doh(tcp, acceptor, answer).await {
                    tracing::debug!("test DoH connection failed: {err:#}");
                }
            });
        }
    });

    Ok(DohServer {
        addr,
        sni,
        root_cert: cert.der().clone(),
    })
}

/// Serve a single DoH client connection: an HTTP/2 POST to `/dns-query` with
/// a DNS wire message as the body, answered with an A/AAAA record for `answer`.
#[cfg(feature = "dns-over-https")]
async fn serve_doh(
    tcp: tokio::net::TcpStream,
    acceptor: tokio_rustls::TlsAcceptor,
    answer: std::net::IpAddr,
) -> Result<()> {
    use bytes::Bytes;

    let tls = acceptor.accept(tcp).await.context("TLS handshake")?;
    let mut conn = h2::server::handshake(tls)
        .await
        .context("HTTP/2 handshake")?;
    while let Some((request, mut resp)) = conn.accept().await.transpose()? {
        if request.method() != http::Method::POST || request.uri().path() != "/dns-query" {
            continue;
        }
        let query = read_body(request.into_body()).await?;
        let reply = doh_reply(&query, answer);
        let response = http::Response::builder()
            .status(http::StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "application/dns-message")
            .body(())?;
        let mut stream = resp.send_response(response, false)?;
        stream.send_data(Bytes::from(reply), true)?;
    }
    Ok(())
}

async fn read_body(mut body: h2::RecvStream) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        data.extend_from_slice(&chunk);
        body.flow_control().release_capacity(chunk.len())?;
    }
    Ok(data)
}

/// Build a DNS wire-format response to `query`, answering A/AAAA questions
/// with `answer`.
#[cfg(feature = "dns-over-https")]
fn doh_reply(query: &[u8], answer: std::net::IpAddr) -> Vec<u8> {
    use hickory_proto::op::{Message, MessageType};
    use hickory_proto::rr::rdata::{A, AAAA};
    use hickory_proto::rr::{RData, Record, RecordType};

    let Ok(req) = Message::from_vec(query) else {
        return Vec::new();
    };
    let mut resp = Message::new(req.metadata.id, MessageType::Response, req.metadata.op_code);
    resp.metadata.recursion_available = true;
    resp.queries = req.queries.clone();
    for q in &req.queries {
        match (q.query_type(), answer) {
            (RecordType::A, std::net::IpAddr::V4(v4)) => {
                resp.answers
                    .push(Record::from_rdata(q.name().clone(), 60, RData::A(A(v4))));
            }
            (RecordType::AAAA, std::net::IpAddr::V6(v6)) => {
                resp.answers.push(Record::from_rdata(
                    q.name().clone(),
                    60,
                    RData::AAAA(AAAA(v6)),
                ));
            }
            _ => {}
        }
    }
    resp.to_vec().unwrap_or_default()
}
