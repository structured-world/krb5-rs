//! TCP transport for Kerberos KDC communication.
//!
//! TCP messages use 4-byte big-endian length framing per RFC 4120 §7.2.2.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::Krb5Error;

use super::{KdcTransport, DEFAULT_TCP_TIMEOUT, MAX_KDC_RESPONSE_SIZE};

/// TCP-only KDC transport with 4-byte big-endian length framing.
///
/// Each request opens a new TCP connection, sends the length-prefixed
/// message, reads the length-prefixed response, and closes the connection.
#[derive(Debug, Clone)]
pub struct TcpTransport {
    /// KDC address (host:port).
    addr: SocketAddr,
    /// Connect and read timeout.
    timeout: Duration,
}

impl TcpTransport {
    /// Create a new TCP transport for the given KDC address.
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            timeout: DEFAULT_TCP_TIMEOUT,
        }
    }

    /// Create a TCP transport with a custom timeout.
    pub fn with_timeout(addr: SocketAddr, timeout: Duration) -> Self {
        Self { addr, timeout }
    }
}

impl KdcTransport for TcpTransport {
    async fn send_recv(&self, _realm: &str, message: &[u8]) -> Result<Vec<u8>, Krb5Error> {
        tcp_send_recv(self.addr, message, self.timeout).await
    }
}

/// Send a length-framed message over TCP and read the response.
pub(crate) async fn tcp_send_recv(
    addr: SocketAddr,
    message: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, Krb5Error> {
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "TCP connect timed out"))?
        .map_err(Krb5Error::Transport)?;

    stream.set_nodelay(true).map_err(Krb5Error::Transport)?;

    // Build length-prefixed message in one buffer to avoid partial writes
    let len_u32: u32 = message.len().try_into().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("KDC request too large: {} bytes", message.len()),
        )
    })?;
    let mut buf = Vec::with_capacity(4 + message.len());
    buf.extend_from_slice(&len_u32.to_be_bytes());
    buf.extend_from_slice(message);

    tokio::time::timeout(timeout, stream.write_all(&buf))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "TCP write timed out"))?
        .map_err(Krb5Error::Transport)?;

    tokio::time::timeout(timeout, stream.flush())
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "TCP flush timed out"))?
        .map_err(Krb5Error::Transport)?;

    // Read 4-byte response length
    let mut len_buf = [0u8; 4];
    tokio::time::timeout(timeout, stream.read_exact(&mut len_buf))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "TCP read timed out"))?
        .map_err(Krb5Error::Transport)?;

    let resp_len = usize::try_from(u32::from_be_bytes(len_buf)).map_err(|_| {
        Krb5Error::Transport(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "KDC response length overflows usize",
        ))
    })?;
    if resp_len > MAX_KDC_RESPONSE_SIZE {
        return Err(Krb5Error::Transport(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("KDC response too large: {resp_len} bytes (max {MAX_KDC_RESPONSE_SIZE})"),
        )));
    }

    let mut resp = vec![0u8; resp_len];
    tokio::time::timeout(timeout, stream.read_exact(&mut resp))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "TCP read body timed out"))?
        .map_err(Krb5Error::Transport)?;

    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    fn framed_len(len: usize) -> [u8; 4] {
        u32::try_from(len)
            .expect("test message length fits in u32")
            .to_be_bytes()
    }

    fn read_len(len_buf: [u8; 4]) -> usize {
        usize::try_from(u32::from_be_bytes(len_buf)).expect("u32 length fits in usize")
    }

    /// Test TCP framing: length prefix is written and response is read correctly.
    #[tokio::test]
    async fn test_tcp_framing_roundtrip() {
        // Start a mock KDC that echoes the request back
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            // Read length-prefixed request
            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).await.expect("read len");
            let req_len = read_len(len_buf);
            let mut req = vec![0u8; req_len];
            stream.read_exact(&mut req).await.expect("read body");

            // Echo back with length prefix
            let resp = b"mock-response";
            let resp_len = framed_len(resp.len());
            stream.write_all(&resp_len).await.expect("write len");
            stream.write_all(resp).await.expect("write body");
            stream.flush().await.expect("flush");
        });

        let transport = TcpTransport::new(addr);
        let result = transport.send_recv("TEST.REALM", b"test-request").await;
        assert_eq!(result.expect("should succeed"), b"mock-response");

        server.await.expect("server task");
    }

    /// Test TCP timeout on unresponsive server.
    #[tokio::test]
    async fn test_tcp_connect_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.expect("accept");
            tokio::time::sleep(Duration::from_secs(10)).await;
        });

        let transport = TcpTransport::with_timeout(addr, Duration::from_millis(50));
        let result = transport.send_recv("TEST.REALM", b"test").await;
        let err = result.expect_err("read should time out");
        assert!(
            err.to_string().contains("timed out"),
            "expected timeout error, got: {err}"
        );

        server.abort();
    }

    /// Test TCP response too large is rejected.
    #[tokio::test]
    async fn test_tcp_response_too_large() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            // Read the request
            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).await.expect("read len");
            let req_len = read_len(len_buf);
            let mut req = vec![0u8; req_len];
            stream.read_exact(&mut req).await.expect("read body");

            // Send response with absurdly large length
            let fake_len = framed_len(MAX_KDC_RESPONSE_SIZE + 1);
            stream.write_all(&fake_len).await.expect("write len");
        });

        let transport = TcpTransport::new(addr);
        let result = transport.send_recv("TEST.REALM", b"test").await;
        assert!(result.is_err());

        let _ = server.await;
    }
}
