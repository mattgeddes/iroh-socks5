//! Example binary for the SOCKS5-over-iroh protocol.
//!
//! Operates as either the local SOCKS5 client or the remote proxy server.
//!
//! # Server
//!
//! ```sh
//! cargo run --example iroh-socks5 -- server
//! ```
//!
//! The server prints its endpoint id. Whitelist which peers may connect with
//! `--allow <endpoint-id>` (repeatable) and/or `--allow-file <path>` (one id
//! per line, `#` comments allowed).
//!
//! By default the server resolves domain targets with the operating system
//! resolver. To keep the queried names private from the exit host's network,
//! resolve them via DNS-over-HTTPS instead:
//!
//! ```sh
//! cargo run --example iroh-socks5 -- server --dns https://dns.google/dns-query
//! ```
//!
//! (Use `--dns-insecure` to skip DoH TLS certificate verification; only for
//! testing.)
//!
//! # Client
//!
//! ```sh
//! cargo run --example iroh-socks5 -- client --remote <server-endpoint-id>
//! ```
//!
//! The client listens on `127.0.0.1:3128` by default (override with `--bind`).
//! Point a SOCKS5 client (e.g. `curl --socks5-hostname 127.0.0.1:3128`) at it.
//!
//! # Custom relay
//!
//! Both sides use the n0 relay by default. To use a self-hosted (or otherwise
//! alternate) relay instead, pass `--relay <url>` to both `server` and
//! `client`, e.g. `--relay https://relay.example.com`. Address lookup still
//! goes through the n0 DNS/Pkarr infrastructure, so the server must be able
//! to publish its addresses there.
//!
//! # Keys
//!
//! Both sides persist their identity in a key file (generated on first run):
//! `iroh-socks5-server.key` and `iroh-socks5-client.key` by default. Use the
//! `key` subcommand to inspect a key file's endpoint id.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use iroh::{EndpointAddr, EndpointId, RelayUrl};
use iroh_socks5::{endpoint_builder_with_relay, Client, Server};

#[derive(Parser)]
#[command(name = "iroh-socks5", version, about = "SOCKS5 proxying over iroh")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the remote SOCKS5-over-iroh server.
    Server {
        /// File to store the private key in (generated if it does not exist).
        #[arg(long, default_value = "iroh-socks5-server.key")]
        key_file: PathBuf,
        /// Endpoint id allowed to connect. Repeatable.
        #[arg(long, action = clap::ArgAction::Append)]
        allow: Vec<String>,
        /// File with allowed endpoint ids, one per line ('#' comments allowed).
        #[arg(long)]
        allow_file: Option<PathBuf>,
        /// Relay server to use instead of the n0 default.
        #[arg(long)]
        relay: Option<RelayUrl>,
        /// Resolve domain targets via DNS-over-HTTPS (e.g.
        /// https://dns.google/dns-query) instead of the system resolver, so
        /// the exit host and its network cannot observe the queried names.
        #[cfg(feature = "dns-over-https")]
        #[arg(long)]
        dns: Option<url::Url>,
        /// Do not verify the TLS certificate of the DoH server (testing only).
        #[cfg(feature = "dns-over-https")]
        #[arg(long, requires = "dns")]
        dns_insecure: bool,
    },
    /// Run the local SOCKS5 proxy that forwards to a remote iroh node.
    Client {
        /// Address the local SOCKS5 proxy listens on.
        #[arg(long, short, default_value = "127.0.0.1:3128")]
        bind: SocketAddr,
        /// File to store the private key in (generated if it does not exist).
        #[arg(long, default_value = "iroh-socks5-client.key")]
        key_file: PathBuf,
        /// Endpoint id of the remote iroh SOCKS5 server.
        #[arg(long)]
        remote: EndpointId,
        /// Relay server to use instead of the n0 default.
        #[arg(long)]
        relay: Option<RelayUrl>,
    },
    /// Print the endpoint id for a key file (generating it if missing).
    Key {
        /// File to store the private key in (generated if it does not exist).
        #[arg(long, default_value = "iroh-socks5.key")]
        key_file: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    match Cli::parse().command {
        Command::Server {
            key_file,
            allow,
            allow_file,
            relay,
            #[cfg(feature = "dns-over-https")]
            dns,
            #[cfg(feature = "dns-over-https")]
            dns_insecure,
        } => {
            run_server(
                key_file,
                allow,
                allow_file,
                relay,
                #[cfg(feature = "dns-over-https")]
                dns,
                #[cfg(feature = "dns-over-https")]
                dns_insecure,
            )
            .await
        }
        Command::Client {
            bind,
            key_file,
            remote,
            relay,
        } => run_client(bind, key_file, remote, relay).await,
        Command::Key { key_file } => {
            let key = iroh_socks5::key::load_or_create(&key_file).await?;
            println!("{}", key.public());
            Ok(())
        }
    }
}

async fn run_server(
    key_file: PathBuf,
    allow: Vec<String>,
    allow_file: Option<PathBuf>,
    relay: Option<RelayUrl>,
    #[cfg(feature = "dns-over-https")] dns: Option<url::Url>,
    #[cfg(feature = "dns-over-https")] dns_insecure: bool,
) -> Result<()> {
    let secret_key = iroh_socks5::key::load_or_create(&key_file).await?;
    let endpoint = endpoint_builder_with_relay(secret_key, relay.clone())
        .bind()
        .await?;

    let mut allowed = HashSet::new();
    for id in &allow {
        allowed.insert(
            id.parse::<EndpointId>()
                .with_context(|| format!("invalid endpoint id: {id}"))?,
        );
    }
    if let Some(path) = &allow_file {
        allowed.extend(read_ids_file(path).await?);
    }
    let n_allow = allowed.len();

    #[cfg(feature = "dns-over-https")]
    let server = match &dns {
        Some(url) => {
            let resolver = iroh_socks5::DnsResolver::from_url(url, dns_insecure).await?;
            Server::with_resolver(endpoint.clone(), allowed, resolver).await?
        }
        None => Server::new(endpoint.clone(), allowed).await?,
    };
    #[cfg(not(feature = "dns-over-https"))]
    let server = Server::new(endpoint.clone(), allowed).await?;
    let id = endpoint.id();
    println!("endpoint id: {id}");
    match relay {
        Some(url) => println!("using relay: {url}"),
        None => println!("using default n0 relay"),
    }
    #[cfg(feature = "dns-over-https")]
    if let Some(url) = &dns {
        println!("resolving domains via DoH: {url}");
    }
    println!("listening for iroh SOCKS5 connections (allow-list size: {n_allow})");

    tokio::select! {
        r = wait_for_shutdown() => r?,
        _ = std::future::pending::<()>() => {}
    }
    server.shutdown().await?;
    Ok(())
}

async fn run_client(
    bind: SocketAddr,
    key_file: PathBuf,
    remote: EndpointId,
    relay: Option<RelayUrl>,
) -> Result<()> {
    let secret_key = iroh_socks5::key::load_or_create(&key_file).await?;
    let endpoint = endpoint_builder_with_relay(secret_key, relay.clone())
        .bind()
        .await?;
    let client = Client::new(endpoint.clone(), EndpointAddr::from(remote));
    println!("our endpoint id: {}", endpoint.id());
    match relay {
        Some(url) => println!("using relay: {url}"),
        None => println!("using default n0 relay"),
    }
    println!("listening on {bind}, proxying to {remote}");

    tokio::select! {
        r = client.run(bind) => r,
        _ = wait_for_shutdown() => {
            endpoint.close().await;
            Ok(())
        }
    }
}

async fn wait_for_shutdown() -> Result<()> {
    tokio::signal::ctrl_c()
        .await
        .context("failed to listen for ctrl-c")?;
    tracing::info!("shutting down");
    Ok(())
}

async fn read_ids_file(path: &PathBuf) -> Result<HashSet<EndpointId>> {
    let text = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("read {}", path.display()))?;
    let mut ids = HashSet::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        ids.insert(
            line.parse::<EndpointId>()
                .with_context(|| format!("invalid endpoint id in {}: {line}", path.display()))?,
        );
    }
    Ok(ids)
}
