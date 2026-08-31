//! SOCKS5 proxying over [iroh].
//!
//! This crate implements a custom iroh protocol that tunnels the SOCKS5 proxy
//! protocol over peer-to-peer QUIC connections, so that a SOCKS5 client can be
//! forwarded to a remote machine without either side having a publicly
//! reachable IP address.
//!
//! # Layout
//!
//! * A local [`Client`] binds a TCP listener, speaks SOCKS5 to anything that
//!   connects, and forwards each session over a single bidirectional iroh
//!   stream to a remote [`Server`].
//! * A remote [`Server`] accepts connections from a configurable allow-list of
//!   [`EndpointId`]s and makes the outbound connection (CONNECT, BIND, or a
//!   UDP association) on behalf of the caller.
//!
//! See the `examples/iroh-socks5.rs` binary for a ready-to-use CLI.

pub mod client;
pub mod dns;
pub mod key;
pub mod protocol;
pub mod relay;
pub mod server;
pub mod socks5;

#[cfg(feature = "test-utils")]
pub mod test_util;

pub use client::Client;
pub use dns::DnsResolver;
pub use iroh::{Endpoint, EndpointAddr, EndpointId, RelayUrl, SecretKey};
pub use protocol::ALPN;
pub use server::Server;

/// Builds an iroh endpoint configured for the SOCKS5-over-iroh protocol.
///
/// Uses the `N0` preset, which enables the default n0 relay and DNS/Pkarr
/// address lookup, so peers can dial each other by [`EndpointId`] alone.
pub fn endpoint_builder(secret_key: SecretKey) -> iroh::endpoint::Builder {
    endpoint_builder_with_relay(secret_key, None)
}

/// Builds an iroh endpoint configured for the SOCKS5-over-iroh protocol,
/// optionally using a custom relay server.
///
/// With `relay == None` this is identical to [`endpoint_builder`]. With
/// `Some(url)` the endpoint uses `url` as its relay instead of the n0
/// default; DNS/Pkarr address lookup stays enabled, so peers still dial each
/// other by [`EndpointId`] alone (as long as the server publishes its
/// addresses).
pub fn endpoint_builder_with_relay(
    secret_key: SecretKey,
    relay: Option<RelayUrl>,
) -> iroh::endpoint::Builder {
    use iroh::endpoint::RelayMode;

    let builder = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        .secret_key(secret_key)
        .alpns(vec![ALPN.to_vec()]);
    match relay {
        Some(url) => builder.relay_mode(RelayMode::custom([url])),
        None => builder,
    }
}

#[cfg(all(test, feature = "test-utils"))]
mod tests {
    use crate::test_util::TestInfra;
    use iroh::SecretKey;

    #[tokio::test]
    async fn endpoint_builder_with_custom_relay_uses_it() -> anyhow::Result<()> {
        let infra = TestInfra::new().await?;
        let endpoint = crate::endpoint_builder_with_relay(
            SecretKey::generate(),
            Some(infra.relay_url.clone()),
        )
        // The local test relay uses a self-signed certificate.
        .ca_tls_config(iroh_relay::tls::CaTlsConfig::insecure_skip_verify())
        .bind()
        .await?;
        infra.wait_online(&endpoint).await?;
        let urls: Vec<_> = endpoint.addr().relay_urls().cloned().collect();
        assert!(
            urls.contains(&infra.relay_url),
            "endpoint relay URLs {urls:?} do not include {}",
            infra.relay_url
        );
        Ok(())
    }
}
