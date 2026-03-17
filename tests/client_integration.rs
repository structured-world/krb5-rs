//! Integration tests for the high-level KerberosClient API.
//!
//! These tests require a running KDC container:
//!   docker compose -f docker-compose.test.yml up -d
//!
//! Run with:
//!   cargo test --features tokio --test client_integration -- --ignored
//!
//! Uses TcpTransport (Docker Desktop on macOS doesn't reliably forward UDP).

use std::net::SocketAddr;

use krb5_rs::client::KerberosClient;
use krb5_rs::transport::TcpTransport;
use krb5_rs::Krb5Error;

const KDC_ADDR: &str = "127.0.0.1:10188";
const REALM: &str = "TEST.REALM";

fn kdc_addr() -> SocketAddr {
    KDC_ADDR.parse().expect("parse KDC address")
}

/// Test: full flow — acquire TGT via KerberosClient.
#[tokio::test]
#[ignore = "requires KDC: docker compose -f docker-compose.test.yml up -d"]
async fn test_client_acquire_tgt() {
    let transport = TcpTransport::new(kdc_addr());
    let client = KerberosClient::new(REALM, transport);

    let cred = client
        .acquire_tgt("testuser", "testpassword")
        .await
        .expect("should acquire TGT");

    assert_eq!(cred.client.to_string(), "testuser");
    assert_eq!(cred.crealm, REALM);
    assert_eq!(cred.server.to_string(), "krbtgt/TEST.REALM");
    assert_eq!(cred.srealm, REALM);
    assert!(
        cred.session_key.keytype == 18 || cred.session_key.keytype == 17,
        "unexpected etype: {}",
        cred.session_key.keytype
    );
}

/// Test: acquire TGT then get service ticket.
#[tokio::test]
#[ignore = "requires KDC: docker compose -f docker-compose.test.yml up -d"]
async fn test_client_get_service_ticket() {
    let transport = TcpTransport::new(kdc_addr());
    let client = KerberosClient::new(REALM, transport);

    let tgt = client
        .acquire_tgt("testuser", "testpassword")
        .await
        .expect("TGT");

    let service_cred = client
        .get_service_ticket(&tgt, "HTTP/server.test.realm")
        .await
        .expect("service ticket");

    assert_eq!(service_cred.server.to_string(), "HTTP/server.test.realm");
    assert_eq!(service_cred.srealm, REALM);
    assert_eq!(service_cred.client.to_string(), "testuser");
    assert!(!service_cred.session_key.key_bytes().is_empty());
    assert_ne!(
        service_cred.session_key.key_bytes(),
        tgt.session_key.key_bytes(),
    );
}

/// Test: wrong password fails.
#[tokio::test]
#[ignore = "requires KDC: docker compose -f docker-compose.test.yml up -d"]
async fn test_client_wrong_password() {
    let transport = TcpTransport::new(kdc_addr());
    let client = KerberosClient::new(REALM, transport);

    let result = client.acquire_tgt("testuser", "wrongpassword").await;
    assert!(
        matches!(
            result,
            Err(Krb5Error::DecryptionFailed) | Err(Krb5Error::KdcError(_))
        ),
        "expected auth failure, got: {result:?}"
    );
}

/// Test: unknown service principal fails.
#[tokio::test]
#[ignore = "requires KDC: docker compose -f docker-compose.test.yml up -d"]
async fn test_client_unknown_service() {
    let transport = TcpTransport::new(kdc_addr());
    let client = KerberosClient::new(REALM, transport);

    let tgt = client
        .acquire_tgt("testuser", "testpassword")
        .await
        .expect("TGT");

    let result = client
        .get_service_ticket(&tgt, "HTTP/nonexistent.example.com")
        .await;
    assert!(matches!(result, Err(Krb5Error::KdcError(_))));
}
