//! Integration tests for the AS exchange against a real MIT KDC.
//!
//! These tests require a running KDC container. Start it with:
//!   docker compose -f docker-compose.test.yml up -d
//!
//! The KDC listens on localhost:10088 with realm TEST.REALM.
//! Test principals:
//!   - testuser@TEST.REALM (password: testpassword)
//!   - testuser2@TEST.REALM (password: password2)

use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::time::Duration;

use krb5_rs::protocol::{AsExchange, AsExchangeConfig, StepResult};
use krb5_rs::types::PrincipalName;
use krb5_rs::Krb5Error;

const KDC_ADDR: &str = "127.0.0.1:10088";
const REALM: &str = "TEST.REALM";

/// Check if the KDC is reachable before running tests.
fn kdc_available() -> bool {
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|sock| {
            sock.set_read_timeout(Some(Duration::from_millis(500)))?;
            sock.send_to(&[0u8; 4], KDC_ADDR)?;
            let mut buf = [0u8; 1024];
            // Any response (even error) means KDC is up
            match sock.recv_from(&mut buf) {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            }
        })
        .unwrap_or(false)
}

/// Send a message to the KDC via UDP, return the response.
fn udp_send(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(Duration::from_secs(5)))?;
    sock.send_to(data, KDC_ADDR)?;
    let mut buf = vec![0u8; 65535];
    let (n, _) = sock.recv_from(&mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

/// Send a message to the KDC via TCP (4-byte length prefix), return the response.
fn tcp_send(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(KDC_ADDR)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    // TCP framing: 4-byte big-endian length prefix
    let len = (data.len() as u32).to_be_bytes();
    stream.write_all(&len)?;
    stream.write_all(data)?;
    stream.flush()?;
    // Read response length
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp)?;
    Ok(resp)
}

/// Drive the AS exchange state machine to completion using UDP transport.
fn drive_exchange(exchange: &mut AsExchange) -> Result<(), Krb5Error> {
    let mut kdc_reply = Vec::new();
    loop {
        match exchange.step(&kdc_reply)? {
            StepResult::SendToKdc { data, .. } => {
                kdc_reply = udp_send(&data).map_err(Krb5Error::Transport)?;
            }
            StepResult::Complete => return Ok(()),
        }
    }
}

/// Test: acquire TGT with correct password via the two-round AS exchange.
///
/// Verifies the full PREAUTH_REQUIRED → PA-ENC-TIMESTAMP → AS-REP flow.
#[test]
fn test_acquire_tgt_with_password() {
    if !kdc_available() {
        eprintln!("SKIP: KDC not available at {KDC_ADDR}. Run: docker compose -f docker-compose.test.yml up -d");
        return;
    }

    let config = AsExchangeConfig::new(PrincipalName::new_principal("testuser"), REALM);
    let mut exchange = AsExchange::new(config, "testpassword");

    drive_exchange(&mut exchange).expect("AS exchange should succeed");

    let cred = exchange.credential().expect("should have credential");
    // Verify credential fields
    assert_eq!(cred.client.to_string(), "testuser");
    assert_eq!(cred.crealm, REALM);
    assert_eq!(cred.server.to_string(), "krbtgt/TEST.REALM");
    assert_eq!(cred.srealm, REALM);
    // Session key should be AES-256 or AES-128
    assert!(
        cred.session_key.keytype == 18 || cred.session_key.keytype == 17,
        "unexpected session key type: {}",
        cred.session_key.keytype
    );
    // Session key bytes should be non-empty
    assert!(!cred.session_key.key_bytes().is_empty());
}

/// Test: acquire TGT for a second user to verify it's not user-specific.
#[test]
fn test_acquire_tgt_second_user() {
    if !kdc_available() {
        eprintln!("SKIP: KDC not available at {KDC_ADDR}");
        return;
    }

    let config = AsExchangeConfig::new(PrincipalName::new_principal("testuser2"), REALM);
    let mut exchange = AsExchange::new(config, "password2");

    drive_exchange(&mut exchange).expect("AS exchange should succeed for testuser2");

    let cred = exchange.credential().expect("should have credential");
    assert_eq!(cred.client.to_string(), "testuser2");
}

/// Test: wrong password produces DecryptionFailed error.
#[test]
fn test_wrong_password_fails() {
    if !kdc_available() {
        eprintln!("SKIP: KDC not available at {KDC_ADDR}");
        return;
    }

    let config = AsExchangeConfig::new(PrincipalName::new_principal("testuser"), REALM);
    let mut exchange = AsExchange::new(config, "wrongpassword");

    let result = drive_exchange(&mut exchange);
    // KDC should reject: either PREAUTH_FAILED (24) or decryption fails client-side
    match result {
        Err(Krb5Error::DecryptionFailed) => {} // Client-side decryption failure
        Err(Krb5Error::KdcError(err)) => {
            assert_eq!(err.error_code, 24, "expected PREAUTH_FAILED (24)");
        }
        Err(other) => panic!("unexpected error: {other}"),
        Ok(()) => panic!("should have failed with wrong password"),
    }
}

/// Test: unknown principal produces KDC_ERR_C_PRINCIPAL_UNKNOWN (6).
#[test]
fn test_unknown_principal_fails() {
    if !kdc_available() {
        eprintln!("SKIP: KDC not available at {KDC_ADDR}");
        return;
    }

    let config = AsExchangeConfig::new(PrincipalName::new_principal("nonexistent_user_xyz"), REALM);
    let mut exchange = AsExchange::new(config, "anypassword");

    let result = drive_exchange(&mut exchange);
    match result {
        Err(Krb5Error::KdcError(err)) => {
            assert_eq!(
                err.error_code, 6,
                "expected C_PRINCIPAL_UNKNOWN (6), got {}",
                err.error_code
            );
        }
        Err(other) => panic!("unexpected error: {other}"),
        Ok(()) => panic!("should have failed with unknown principal"),
    }
}

/// Test: TCP transport also works (for completeness).
#[test]
fn test_acquire_tgt_via_tcp() {
    if !kdc_available() {
        eprintln!("SKIP: KDC not available at {KDC_ADDR}");
        return;
    }

    let config = AsExchangeConfig::new(PrincipalName::new_principal("testuser"), REALM);
    let mut exchange = AsExchange::new(config, "testpassword");

    let mut kdc_reply = Vec::new();
    let result = loop {
        match exchange.step(&kdc_reply) {
            Ok(StepResult::SendToKdc { data, .. }) => match tcp_send(&data) {
                Ok(resp) => kdc_reply = resp,
                Err(e) => break Err(Krb5Error::Transport(e)),
            },
            Ok(StepResult::Complete) => break Ok(()),
            Err(e) => break Err(e),
        }
    };

    result.expect("TCP AS exchange should succeed");
    let cred = exchange.credential().expect("should have credential");
    assert_eq!(cred.client.to_string(), "testuser");
}
