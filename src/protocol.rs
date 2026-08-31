//! The SOCKS5-over-iroh wire protocol.
//!
//! A single SOCKS5 session is carried over one bidirectional iroh stream:
//!
//! 1. The connecting side sends a length-prefixed, postcard-encoded [`Request`].
//! 2. The accepting side answers with one or more length-prefixed [`Reply`]es.
//! 3. For [`Request::Connect`] and [`Request::Bind`] the stream then carries
//!    raw bytes in both directions. For [`Request::UdpAssociate`] the stream
//!    carries length-prefixed [`Datagram`] messages.
//!
//! The framing is a little-endian `u32` byte length followed by a postcard
//! encoded payload. See [`write_frame`] and [`read_frame`].

use std::net::SocketAddr;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The ALPN identifying the SOCKS5-over-iroh protocol.
pub const ALPN: &[u8] = b"iroh-socks5/1";

/// Maximum size of a single framed message. Kept well above the largest
/// possible UDP datagram so that whole datagrams always fit in one frame.
const MAX_FRAME_SIZE: usize = 128 * 1024;

/// The address a request is targeting.
///
/// Domains are kept unresolved so that name resolution happens on the
/// endpoint that actually makes the outbound connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl TargetAddr {
    /// The port this address refers to.
    pub fn port(&self) -> u16 {
        match self {
            TargetAddr::Ip(addr) => addr.port(),
            TargetAddr::Domain(_, port) => *port,
        }
    }
}

impl std::fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TargetAddr::Ip(addr) => write!(f, "{addr}"),
            TargetAddr::Domain(domain, port) => write!(f, "{domain}:{port}"),
        }
    }
}

/// A request sent from the SOCKS5 client to the remote proxy endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    /// Establish a TCP connection to `target` and relay bytes.
    Connect(TargetAddr),
    /// Bind a listener that an incoming connection will be relayed to.
    Bind(TargetAddr),
    /// Relay UDP datagrams for a SOCKS5 UDP association.
    UdpAssociate(TargetAddr),
}

/// A reply sent from the remote proxy endpoint back to the SOCKS5 client.
///
/// `code` is a SOCKS5 reply code, see [`crate::socks5::REP_SUCCEEDED`] and
/// friends. `addr` is the address to report as `BND.ADDR`/`BND.PORT`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reply {
    pub code: u8,
    pub addr: Option<SocketAddr>,
}

impl Reply {
    /// A successful reply with an optional bound address.
    pub fn ok(addr: Option<SocketAddr>) -> Self {
        Self {
            code: crate::socks5::REP_SUCCEEDED,
            addr,
        }
    }

    /// A failed reply with the given SOCKS5 reply code.
    pub fn fail(code: u8) -> Self {
        Self { code, addr: None }
    }
}

/// A single UDP datagram relayed over the stream.
///
/// `addr` is the destination when sent client-to-server and the source when
/// sent server-to-client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Datagram {
    pub addr: TargetAddr,
    pub data: Bytes,
}

/// Serializes `msg` and writes it to `writer` as a length-prefixed frame.
pub async fn write_frame<W, T>(writer: &mut W, msg: &T) -> Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let bytes = postcard::to_stdvec(msg).context("encode frame")?;
    if bytes.len() > MAX_FRAME_SIZE {
        bail!("frame too large: {} bytes", bytes.len());
    }
    writer
        .write_all(&(bytes.len() as u32).to_le_bytes())
        .await?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

/// Reads a length-prefixed frame, deserializing it into `T`.
///
/// Returns `Ok(None)` on a clean end-of-stream (the peer finished its send
/// half). A truncated frame is reported as an error.
pub async fn read_frame<R, T>(reader: &mut R) -> Result<Option<T>>
where
    R: AsyncRead + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let mut len_buf = [0u8; 4];
    match reader.read(&mut len_buf[..1]).await {
        Ok(0) => return Ok(None),
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    reader.read_exact(&mut len_buf[1..]).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_FRAME_SIZE {
        bail!("frame too large: {len} bytes");
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    let msg = postcard::from_bytes(&buf).context("decode frame")?;
    Ok(Some(msg))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use super::*;

    #[test]
    fn target_addr_roundtrip() {
        for target in [
            TargetAddr::Ip(SocketAddr::from((Ipv4Addr::LOCALHOST, 8080))),
            TargetAddr::Domain("example.com".to_string(), 443),
        ] {
            let bytes = postcard::to_stdvec(&target).unwrap();
            let back: TargetAddr = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(target, back);
        }
    }

    #[tokio::test]
    async fn frames_roundtrip() {
        use tokio::io::duplex;

        let (mut a, mut b) = duplex(4096);
        let req = Request::Connect(TargetAddr::Domain("example.com".into(), 80));
        write_frame(&mut a, &req).await.unwrap();
        let got: Option<Request> = read_frame(&mut b).await.unwrap();
        assert_eq!(got, Some(req));
    }

    #[tokio::test]
    async fn read_frame_eof() {
        use tokio::io::duplex;

        let (a, mut b) = duplex(4096);
        drop(a);
        assert!(read_frame::<_, Request>(&mut b).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn read_frame_truncated() {
        use tokio::io::duplex;

        let (mut a, mut b) = duplex(4096);
        // A length that promises more bytes than we send.
        a.write_all(&42u32.to_le_bytes()).await.unwrap();
        a.write_all(b"short").await.unwrap();
        drop(a);
        assert!(read_frame::<_, Request>(&mut b).await.is_err());
    }
}
