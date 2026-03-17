//! UDP transport for Kerberos KDC communication.
//!
//! UDP messages are sent as raw datagrams — no length framing.
//! Per RFC 4120 §7.2.1, UDP is the default transport for Kerberos.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;

use crate::Krb5Error;

use super::{KdcTransport, DEFAULT_UDP_TIMEOUT, MAX_UDP_SIZE};

/// UDP-only KDC transport.
///
/// Sends the request as a single UDP datagram and waits for a response.
/// No length framing — the datagram boundary provides message delimitation.
#[derive(Debug, Clone)]
pub struct UdpTransport {
    /// KDC address (host:port).
    addr: SocketAddr,
    /// Receive timeout.
    timeout: Duration,
}

impl UdpTransport {
    /// Create a new UDP transport for the given KDC address.
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            timeout: DEFAULT_UDP_TIMEOUT,
        }
    }

    /// Create a UDP transport with a custom timeout.
    pub fn with_timeout(addr: SocketAddr, timeout: Duration) -> Self {
        Self { addr, timeout }
    }
}

impl KdcTransport for UdpTransport {
    async fn send_recv(&self, _realm: &str, message: &[u8]) -> Result<Vec<u8>, Krb5Error> {
        udp_send_recv(self.addr, message, self.timeout).await
    }
}

/// Send a raw UDP datagram and read the response.
pub(crate) async fn udp_send_recv(
    addr: SocketAddr,
    message: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, Krb5Error> {
    // Bind to an ephemeral port matching the KDC address family
    let bind_addr = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind_addr)
        .await
        .map_err(Krb5Error::Transport)?;
    socket.connect(addr).await.map_err(Krb5Error::Transport)?;

    socket.send(message).await.map_err(Krb5Error::Transport)?;

    let mut buf = vec![0u8; MAX_UDP_SIZE];
    let n = tokio::time::timeout(timeout, socket.recv(&mut buf))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "UDP receive timed out"))?
        .map_err(Krb5Error::Transport)?;

    buf.truncate(n);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test UDP round-trip with a mock server.
    #[tokio::test]
    async fn test_udp_roundtrip() {
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind server");
        let server_addr = server.local_addr().expect("server addr");

        let server_task = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_UDP_SIZE];
            let (n, src) = server.recv_from(&mut buf).await.expect("recv");
            // Echo back with "reply:" prefix
            let mut reply = b"reply:".to_vec();
            reply.extend_from_slice(&buf[..n]);
            server.send_to(&reply, src).await.expect("send");
        });

        let transport = UdpTransport::new(server_addr);
        let result = transport
            .send_recv("TEST.REALM", b"hello")
            .await
            .expect("should succeed");
        assert_eq!(result, b"reply:hello");

        server_task.await.expect("server task");
    }

    /// Test UDP timeout when server doesn't respond.
    #[tokio::test]
    async fn test_udp_timeout() {
        // Bind a socket but never read from it
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let addr = server.local_addr().expect("addr");

        let transport = UdpTransport::with_timeout(addr, Duration::from_millis(50));
        let result = transport.send_recv("TEST.REALM", b"hello").await;
        assert!(result.is_err());

        // Keep server alive until test completes
        drop(server);
    }
}
