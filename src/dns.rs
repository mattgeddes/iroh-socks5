//! Domain name resolution for the remote proxy endpoint.
//!
//! The remote [`Server`](crate::Server) resolves domain targets on the exit
//! node. By default it uses the operating system resolver ([`DnsResolver::System`]),
//! which leaks the queried names to whatever DNS servers the exit host is
//! configured with. With the `dns-over-https` feature a [`DnsResolver::DoH`]
//! resolver can be used instead, so queries travel encrypted to a
//! DNS-over-HTTPS server and the exit host's network cannot observe them.

use std::net::SocketAddr;

#[cfg(feature = "dns-over-https")]
use std::net::IpAddr;
#[cfg(feature = "dns-over-https")]
use std::sync::Arc;

use anyhow::Result;

#[cfg(feature = "dns-over-https")]
use anyhow::{bail, Context};
#[cfg(feature = "dns-over-https")]
use hickory_resolver::config::{NameServerConfig, ResolverConfig};

/// How domain targets are resolved.
#[derive(Clone)]
pub enum DnsResolver {
    /// The operating system resolver (via `tokio::net::lookup_host`).
    System,
    /// A DNS-over-HTTPS resolver.
    #[cfg(feature = "dns-over-https")]
    DoH(Box<hickory_resolver::TokioResolver>),
}

impl std::fmt::Debug for DnsResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsResolver::System => write!(f, "System"),
            #[cfg(feature = "dns-over-https")]
            DnsResolver::DoH(_) => write!(f, "DoH"),
        }
    }
}

impl DnsResolver {
    /// The operating system resolver.
    pub fn system() -> Self {
        DnsResolver::System
    }

    /// Resolve `host` to a set of socket addresses.
    pub async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        match self {
            DnsResolver::System => {
                let addrs = tokio::net::lookup_host((host, port)).await?;
                Ok(addrs.collect())
            }
            #[cfg(feature = "dns-over-https")]
            DnsResolver::DoH(resolver) => {
                let lookup = resolver.lookup_ip(host).await?;
                Ok(lookup.iter().map(|ip| SocketAddr::new(ip, port)).collect())
            }
        }
    }

    /// Build a DoH resolver from an `https://` URL such as
    /// `https://dns.google/dns-query`.
    ///
    /// The host part is used for the TLS server name (SNI); if it is a
    /// hostname it is first resolved through the system resolver, since
    /// hickory connects to a concrete IP. The port defaults to 443 and the
    /// path to `/dns-query`. With `insecure_skip_verify` set, the server's
    /// TLS certificate is not verified (use only for testing).
    #[cfg(feature = "dns-over-https")]
    pub async fn from_url(url: &url::Url, insecure_skip_verify: bool) -> Result<Self> {
        use hickory_resolver::net::runtime::TokioRuntimeProvider;
        use hickory_resolver::{TlsConfig, TokioResolver};

        if url.scheme() != "https" {
            bail!("DNS-over-HTTPS requires an https URL, got: {url}");
        }
        let host = url
            .host_str()
            .with_context(|| format!("DoH URL has no host: {url}"))?;
        let port = url.port().unwrap_or(443);
        let path = match url.path() {
            "" | "/" => "/dns-query".to_string(),
            path => path.to_string(),
        };

        // hickory needs a concrete IP to connect to; the hostname is only
        // used as the TLS server name.
        let ips = if let Ok(ip) = host.parse::<IpAddr>() {
            vec![ip]
        } else {
            let addrs = tokio::net::lookup_host((host, port)).await?;
            let ips: Vec<_> = addrs.map(|addr| addr.ip()).collect();
            if ips.is_empty() {
                bail!("no addresses found for DoH host: {host}");
            }
            ips
        };

        let server_name = Arc::<str>::from(host);
        let path = Arc::<str>::from(path.as_str());
        let mut config = ResolverConfig::from_parts(None, Vec::new(), Vec::new());
        for ip in ips {
            config.add_name_server(name_server(ip, server_name.clone(), port, path.clone())?);
        }

        let mut builder =
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
        if insecure_skip_verify {
            let mut tls = TlsConfig::new()?;
            tls.insecure_skip_verify();
            builder = builder.with_tls_config(tls.config);
        }
        let resolver = builder.build()?;
        Ok(DnsResolver::DoH(Box::new(resolver)))
    }
}

/// Build a DoH [`NameServerConfig`] for `ip`, connecting on `port` with the
/// given SNI and query path.
#[cfg(feature = "dns-over-https")]
fn name_server(
    ip: IpAddr,
    server_name: Arc<str>,
    port: u16,
    path: Arc<str>,
) -> Result<NameServerConfig> {
    if port == 443 {
        return Ok(NameServerConfig::https(ip, server_name, Some(path)));
    }
    // hickory's public constructor fixes the port at 443, so to honor a
    // custom port we build the config through its serde representation.
    let config: ResolverConfig = serde_json::from_value(serde_json::json!({
        "name_servers": [{
            "ip": ip.to_string(),
            "connections": [{
                "port": port,
                "protocol": {
                    "type": "https",
                    "server_name": server_name,
                    "path": path,
                },
            }],
        }],
    }))?;
    Ok(config
        .name_servers
        .into_iter()
        .next()
        .expect("constructed config has one name server"))
}
