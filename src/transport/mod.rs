//! KDC transport layer.
//!
//! Provides async transport implementations for communicating with Kerberos
//! KDCs over UDP, TCP, or both (with automatic fallback).
//!
//! # Transport Trait
//!
//! All transports implement [`KdcTransport`], which provides a single
//! `send_recv` method for request-response exchanges with a KDC.
//!
//! # Implementations
//!
//! - [`TcpTransport`] — TCP-only with 4-byte big-endian length framing.
//! - [`UdpTransport`] — UDP-only, raw datagrams.
//! - [`UdpTcpTransport`] — UDP first, automatic fallback to TCP on
//!   `KRB_ERR_RESPONSE_TOO_BIG`.

mod tcp;
mod udp;
mod udp_tcp;

pub use tcp::TcpTransport;
pub use udp::UdpTransport;
pub use udp_tcp::UdpTcpTransport;

use crate::Krb5Error;

/// Maximum acceptable KDC response size (1 MiB).
///
/// Protects against allocating arbitrarily large buffers from an untrusted
/// 4-byte length prefix in TCP framing.
pub const MAX_KDC_RESPONSE_SIZE: usize = 1024 * 1024;

/// Default TCP connect + read timeout.
pub const DEFAULT_TCP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Default UDP receive timeout.
pub const DEFAULT_UDP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Maximum UDP datagram size for Kerberos (64 KiB).
const MAX_UDP_SIZE: usize = 65535;

/// Async transport for communicating with a Kerberos KDC.
///
/// The transport handles network-level concerns (framing, timeouts, retries)
/// and presents a simple request-response interface. Realm routing is the
/// caller's responsibility — the transport sends to a fixed address.
pub trait KdcTransport: Send + Sync {
    /// Send a DER-encoded Kerberos message to the KDC and return the response.
    ///
    /// The `realm` parameter is provided for transports that need it for
    /// KDC discovery (e.g., DNS SRV). Fixed-address transports may ignore it.
    fn send_recv(
        &self,
        realm: &str,
        message: &[u8],
    ) -> impl std::future::Future<Output = Result<Vec<u8>, Krb5Error>> + Send;
}
