//! Codec for the SOCKS5 client protocol (RFC 1928).
//!
//! This module implements the wire format only: the greeting negotiation,
//! request parsing, reply writing and the UDP request header used for
//! `UDP ASSOCIATE`. It never performs any network I/O itself.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::protocol::TargetAddr;

pub const VERSION: u8 = 0x05;

pub const METHOD_NO_AUTH: u8 = 0x00;
pub const METHOD_NO_ACCEPTABLE: u8 = 0xff;

pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_BIND: u8 = 0x02;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

pub const REP_SUCCEEDED: u8 = 0x00;
pub const REP_GENERAL_FAILURE: u8 = 0x01;
pub const REP_NOT_ALLOWED: u8 = 0x02;
pub const REP_NETWORK_UNREACHABLE: u8 = 0x03;
pub const REP_HOST_UNREACHABLE: u8 = 0x04;
pub const REP_CONNECTION_REFUSED: u8 = 0x05;
pub const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
pub const REP_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

/// A parsed SOCKS5 request, i.e. everything after the greeting.
#[derive(Debug, Clone)]
pub struct Socks5Request {
    pub command: u8,
    pub target: TargetAddr,
}

/// Performs the SOCKS5 greeting, selecting the no-auth method.
///
/// Writes the chosen method before returning. Returns an error (after having
/// written `0xFF`) when the client does not offer the no-auth method.
pub async fn negotiate<S>(stream: &mut S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let version = stream.read_u8().await?;
    if version != VERSION {
        bail!("unsupported SOCKS version: {version}");
    }
    let nmethods = stream.read_u8().await?;
    let mut methods = vec![0u8; nmethods as usize];
    stream.read_exact(&mut methods).await?;
    let method = if methods.contains(&METHOD_NO_AUTH) {
        METHOD_NO_AUTH
    } else {
        METHOD_NO_ACCEPTABLE
    };
    stream.write_all(&[VERSION, method]).await?;
    stream.flush().await?;
    if method == METHOD_NO_ACCEPTABLE {
        bail!("no acceptable authentication method");
    }
    Ok(())
}

/// Reads a SOCKS5 request (version, command, reserved, target).
pub async fn read_request<R>(stream: &mut R) -> Result<Socks5Request>
where
    R: AsyncRead + Unpin,
{
    let version = stream.read_u8().await?;
    if version != VERSION {
        bail!("unsupported SOCKS version: {version}");
    }
    let command = stream.read_u8().await?;
    let rsv = stream.read_u8().await?;
    if rsv != 0 {
        bail!("invalid reserved byte: {rsv}");
    }
    let target = read_target(stream).await?;
    Ok(Socks5Request { command, target })
}

/// Writes a SOCKS5 reply. A missing address is reported as `0.0.0.0:0`.
pub async fn write_reply<W>(stream: &mut W, code: u8, addr: Option<SocketAddr>) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let target = match addr {
        Some(addr) => TargetAddr::Ip(addr),
        None => TargetAddr::Ip(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))),
    };
    let mut buf = vec![VERSION, code, 0x00];
    buf.extend_from_slice(&target_to_bytes(&target));
    stream.write_all(&buf).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_target<R>(stream: &mut R) -> Result<TargetAddr>
where
    R: AsyncRead + Unpin,
{
    let atyp = stream.read_u8().await?;
    let addr = match atyp {
        ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            TargetAddr::Ip(SocketAddr::from((Ipv4Addr::from(octets), 0)))
        }
        ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            TargetAddr::Ip(SocketAddr::from((Ipv6Addr::from(octets), 0)))
        }
        ATYP_DOMAIN => {
            let len = stream.read_u8().await?;
            let mut buf = vec![0u8; len as usize];
            stream.read_exact(&mut buf).await?;
            let domain = String::from_utf8(buf).context("invalid domain name")?;
            TargetAddr::Domain(domain, 0)
        }
        _ => bail!("unsupported address type: {atyp}"),
    };
    let port = stream.read_u16().await?;
    Ok(match addr {
        TargetAddr::Ip(addr) => TargetAddr::Ip(SocketAddr::new(addr.ip(), port)),
        TargetAddr::Domain(domain, _) => TargetAddr::Domain(domain, port),
    })
}

/// Encodes a target as an SOCKS5 address (`ATYP` + address + port).
pub fn target_to_bytes(target: &TargetAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(22);
    match target {
        TargetAddr::Ip(SocketAddr::V4(addr)) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&addr.ip().octets());
            out.extend_from_slice(&addr.port().to_be_bytes());
        }
        TargetAddr::Ip(SocketAddr::V6(addr)) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&addr.ip().octets());
            out.extend_from_slice(&addr.port().to_be_bytes());
        }
        TargetAddr::Domain(domain, port) => {
            out.push(ATYP_DOMAIN);
            out.push(domain.len() as u8);
            out.extend_from_slice(domain.as_bytes());
            out.extend_from_slice(&port.to_be_bytes());
        }
    }
    out
}

/// Parses a SOCKS5 UDP packet (RFC 1928 section 7) into `(frag, target, data)`.
///
/// Returns `None` for malformed packets or unsupported address types. UDP
/// fragmentation is signalled via the returned `frag` byte and must be handled
/// by the caller.
pub fn parse_udp_packet(packet: &[u8]) -> Option<(u8, TargetAddr, &[u8])> {
    if packet.len() < 4 {
        return None;
    }
    let frag = packet[2];
    let atyp = packet[3];
    let mut idx = 4;
    match atyp {
        ATYP_IPV4 => {
            let bytes = packet.get(idx..idx + 4)?;
            idx += 4;
            let ip = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
            let port = u16::from_be_bytes([*packet.get(idx)?, *packet.get(idx + 1)?]);
            let data = packet.get(idx + 2..)?;
            Some((frag, TargetAddr::Ip(SocketAddr::new(ip.into(), port)), data))
        }
        ATYP_IPV6 => {
            let bytes = packet.get(idx..idx + 16)?;
            idx += 16;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(bytes);
            let port = u16::from_be_bytes([*packet.get(idx)?, *packet.get(idx + 1)?]);
            let data = packet.get(idx + 2..)?;
            Some((
                frag,
                TargetAddr::Ip(SocketAddr::new(Ipv6Addr::from(octets).into(), port)),
                data,
            ))
        }
        ATYP_DOMAIN => {
            let len = *packet.get(idx)? as usize;
            idx += 1;
            let bytes = packet.get(idx..idx + len)?;
            idx += len;
            let domain = std::str::from_utf8(bytes).ok()?.to_string();
            let port = u16::from_be_bytes([*packet.get(idx)?, *packet.get(idx + 1)?]);
            let data = packet.get(idx + 2..)?;
            Some((frag, TargetAddr::Domain(domain, port), data))
        }
        _ => None,
    }
}

/// Encodes a SOCKS5 UDP packet for a relayed datagram (all zeros RSV/FRAG).
pub fn format_udp_packet(target: &TargetAddr, data: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8, 0, 0];
    out.extend_from_slice(&target_to_bytes(target));
    out.extend_from_slice(data);
    out
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn parse_udp_ipv4() {
        let packet = [0, 0, 0, 1, 127, 0, 0, 1, 0x04, 0xd2, b'h', b'i'];
        let (frag, target, data) = parse_udp_packet(&packet).unwrap();
        assert_eq!(frag, 0);
        assert_eq!(
            target,
            TargetAddr::Ip(SocketAddr::from((Ipv4Addr::LOCALHOST, 1234)))
        );
        assert_eq!(data, b"hi");
    }

    #[test]
    fn parse_udp_domain() {
        let packet = [
            0, 0, 0, 3, 5, b'h', b'e', b'l', b'l', b'o', 0x01, 0xbb, b'x',
        ];
        let (frag, target, data) = parse_udp_packet(&packet).unwrap();
        assert_eq!(frag, 0);
        assert_eq!(target, TargetAddr::Domain("hello".into(), 443));
        assert_eq!(data, b"x");
    }

    #[test]
    fn format_roundtrip() {
        let target = TargetAddr::Ip(SocketAddr::from((Ipv4Addr::LOCALHOST, 53)));
        let packet = format_udp_packet(&target, b"query");
        assert_eq!(&packet[..4], &[0, 0, 0, 1]);
        let (frag, parsed, data) = parse_udp_packet(&packet).unwrap();
        assert_eq!(frag, 0);
        assert_eq!(parsed, target);
        assert_eq!(data, b"query");
    }

    #[tokio::test]
    async fn negotiate_accepts_no_auth() {
        use tokio::io::duplex;
        let (mut a, mut b) = duplex(64);
        a.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        negotiate(&mut b).await.unwrap();
        let mut out = [0u8; 2];
        a.read_exact(&mut out).await.unwrap();
        assert_eq!(out, [0x05, 0x00]);
    }

    #[tokio::test]
    async fn negotiate_rejects_unknown_methods() {
        use tokio::io::duplex;
        let (mut a, mut b) = duplex(64);
        a.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        assert!(negotiate(&mut b).await.is_err());
        let mut out = [0u8; 2];
        a.read_exact(&mut out).await.unwrap();
        assert_eq!(out, [0x05, 0xff]);
    }

    #[tokio::test]
    async fn read_request_ipv4() {
        use tokio::io::duplex;
        let (mut a, mut b) = duplex(64);
        a.write_all(&[0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x1f, 0x90])
            .await
            .unwrap();
        let req = read_request(&mut b).await.unwrap();
        assert_eq!(req.command, CMD_CONNECT);
        assert_eq!(
            req.target,
            TargetAddr::Ip(SocketAddr::from((Ipv4Addr::new(1, 2, 3, 4), 8080)))
        );
    }

    #[tokio::test]
    async fn read_request_domain() {
        use tokio::io::duplex;
        let (mut a, mut b) = duplex(64);
        a.write_all(&[
            0x05, 0x03, 0x00, 0x03, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o',
            b'm', 0x01, 0xbb,
        ])
        .await
        .unwrap();
        let req = read_request(&mut b).await.unwrap();
        assert_eq!(req.command, CMD_UDP_ASSOCIATE);
        assert_eq!(req.target, TargetAddr::Domain("example.com".into(), 443));
    }

    #[tokio::test]
    async fn write_reply_ipv4() {
        use tokio::io::duplex;
        let (mut a, mut b) = duplex(64);
        write_reply(
            &mut b,
            REP_SUCCEEDED,
            Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 1080))),
        )
        .await
        .unwrap();
        let mut out = [0u8; 10];
        a.read_exact(&mut out).await.unwrap();
        assert_eq!(&out[..4], &[0x05, 0x00, 0x00, 0x01]);
        assert_eq!(&out[4..8], &[127, 0, 0, 1]);
        assert_eq!(&out[8..10], &1080u16.to_be_bytes());
    }
}
