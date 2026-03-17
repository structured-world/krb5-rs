//! Combined UDP/TCP transport with automatic fallback.
//!
//! Sends via UDP first. If the KDC responds with `KRB_ERR_RESPONSE_TOO_BIG`
//! (error code 52), automatically retries over TCP. This matches the behavior
//! described in RFC 4120 §7.2.1.

use std::net::SocketAddr;
use std::time::Duration;

use crate::Krb5Error;

use super::tcp::tcp_send_recv;
use super::udp::udp_send_recv;
use super::{KdcTransport, DEFAULT_TCP_TIMEOUT, DEFAULT_UDP_TIMEOUT};

/// KRB_ERR_RESPONSE_TOO_BIG error code (52).
/// Used to detect when UDP response was too large and TCP retry is needed.
const KRB_ERR_RESPONSE_TOO_BIG: i32 = 52;

/// Combined UDP/TCP transport.
///
/// Tries UDP first, then falls back to TCP if the response indicates the
/// message was too large for UDP. This is the recommended transport for
/// general use.
#[derive(Debug, Clone)]
pub struct UdpTcpTransport {
    /// KDC address (host:port).
    addr: SocketAddr,
    /// UDP receive timeout.
    udp_timeout: Duration,
    /// TCP connect + read timeout.
    tcp_timeout: Duration,
}

impl UdpTcpTransport {
    /// Create a new UDP/TCP transport for the given KDC address.
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            udp_timeout: DEFAULT_UDP_TIMEOUT,
            tcp_timeout: DEFAULT_TCP_TIMEOUT,
        }
    }

    /// Create a transport with custom timeouts.
    pub fn with_timeouts(
        addr: SocketAddr,
        udp_timeout: Duration,
        tcp_timeout: Duration,
    ) -> Self {
        Self {
            addr,
            udp_timeout,
            tcp_timeout,
        }
    }
}

impl KdcTransport for UdpTcpTransport {
    async fn send_recv(&self, _realm: &str, message: &[u8]) -> Result<Vec<u8>, Krb5Error> {
        // Try UDP first
        let udp_response = udp_send_recv(self.addr, message, self.udp_timeout).await?;

        // Check if the response is a KRB-ERROR with RESPONSE_TOO_BIG
        if is_response_too_big(&udp_response) {
            // Retry over TCP
            return tcp_send_recv(self.addr, message, self.tcp_timeout).await;
        }

        Ok(udp_response)
    }
}

/// Check if a DER-encoded response is a KRB-ERROR with error_code 52
/// (RESPONSE_TOO_BIG). Uses minimal parsing to avoid a full ASN.1 decode.
fn is_response_too_big(data: &[u8]) -> bool {
    // Quick check: try full ASN.1 decode of KRB-ERROR
    if let Ok(krb_error) = rasn::der::decode::<crate::types::KrbErrorMsg>(data) {
        return krb_error.error_code == KRB_ERR_RESPONSE_TOO_BIG;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, UdpSocket};

    /// Test: successful UDP response (no fallback needed).
    #[tokio::test]
    async fn test_udp_success_no_fallback() {
        let udp_server = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
        let addr = udp_server.local_addr().expect("addr");

        let server_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            let (_n, src) = udp_server.recv_from(&mut buf).await.expect("recv");
            // Reply with non-error data
            let reply = b"ok-response";
            udp_server.send_to(reply, src).await.expect("send");
        });

        let transport = UdpTcpTransport::new(addr);
        let result = transport
            .send_recv("TEST.REALM", b"request")
            .await
            .expect("should succeed");
        assert_eq!(result, b"ok-response");

        server_task.await.expect("server");
    }

    /// Test: UDP returns RESPONSE_TOO_BIG, automatic TCP fallback.
    #[tokio::test]
    async fn test_udp_too_big_falls_back_to_tcp() {
        // Build a KRB-ERROR with error_code 52
        let too_big_error = build_response_too_big_error();

        // UDP server: returns RESPONSE_TOO_BIG
        let udp_server = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
        let udp_addr = udp_server.local_addr().expect("udp addr");
        let port = udp_addr.port();

        // TCP server on same port: returns the real response
        let tcp_listener = TcpListener::bind(format!("127.0.0.1:{port}"))
            .await
            .expect("bind tcp");

        let udp_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            let (_n, src) = udp_server.recv_from(&mut buf).await.expect("udp recv");
            udp_server
                .send_to(&too_big_error, src)
                .await
                .expect("udp send");
        });

        let tcp_task = tokio::spawn(async move {
            let (mut stream, _) = tcp_listener.accept().await.expect("tcp accept");
            // Read length-prefixed request
            let mut len_buf = [0u8; 4];
            tokio::io::AsyncReadExt::read_exact(&mut stream, &mut len_buf)
                .await
                .expect("tcp read len");
            let req_len = u32::from_be_bytes(len_buf) as usize;
            let mut req = vec![0u8; req_len];
            tokio::io::AsyncReadExt::read_exact(&mut stream, &mut req)
                .await
                .expect("tcp read body");

            // Send TCP response
            let resp = b"tcp-response";
            let resp_len = (resp.len() as u32).to_be_bytes();
            stream.write_all(&resp_len).await.expect("tcp write len");
            stream.write_all(resp).await.expect("tcp write body");
            stream.flush().await.expect("tcp flush");
        });

        let transport = UdpTcpTransport::new(udp_addr);
        let result = transport
            .send_recv("TEST.REALM", b"request")
            .await
            .expect("should succeed via TCP fallback");
        assert_eq!(result, b"tcp-response");

        udp_task.await.expect("udp task");
        tcp_task.await.expect("tcp task");
    }

    /// Build a DER-encoded KRB-ERROR with error_code 52 (RESPONSE_TOO_BIG).
    fn build_response_too_big_error() -> Vec<u8> {
        use crate::types::{KrbErrorMsg, PrincipalName};
        use chrono::Utc;
        use rasn::types::GeneralString;

        let now = Utc::now().with_timezone(&chrono::FixedOffset::east_opt(0).expect("utc"));
        let krb_error = KrbErrorMsg {
            pvno: 5,
            msg_type: 30,
            ctime: None,
            cusec: None,
            stime: now,
            susec: 0,
            error_code: 52,
            crealm: None,
            cname: None,
            realm: GeneralString::from_bytes(b"TEST.REALM").expect("realm"),
            sname: PrincipalName::new_srv_inst("krbtgt", "TEST.REALM"),
            e_text: None,
            e_data: None,
        };
        rasn::der::encode(&krb_error).expect("encode KRB-ERROR")
    }
}
