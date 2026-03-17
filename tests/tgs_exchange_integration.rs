//! Integration tests for the TGS exchange against a real MIT KDC.
//!
//! These tests require a running KDC container:
//!   docker compose -f docker-compose.test.yml up -d
//!
//! Run with:
//!   cargo test --test tgs_exchange_integration -- --ignored
//!
//! The KDC listens on localhost:10188 with realm TEST.REALM.
//! A second KDC listens on localhost:10288 with realm OTHER.REALM.
//! Test principals:
//!   - testuser@TEST.REALM (password: testpassword)
//!   - HTTP/server.test.realm@TEST.REALM (keytab, random key)
//!   - HTTP/service.other.realm@OTHER.REALM (keytab, random key)
//!
//! Cross-realm trust: TEST.REALM <-> OTHER.REALM (bidirectional)

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use krb5_rs::protocol::ErrorCode;
use krb5_rs::protocol::{
    AsExchange, AsExchangeConfig, Credential, StepResult, TgsExchange, TgsOptions, TgsStepResult,
};
use krb5_rs::types::PrincipalName;
use krb5_rs::Krb5Error;

const KDC_ADDR: &str = "127.0.0.1:10188";
const KDC_OTHER_ADDR: &str = "127.0.0.1:10288";
const REALM: &str = "TEST.REALM";
const OTHER_REALM: &str = "OTHER.REALM";

/// Maximum acceptable KDC response size (1 MiB).
const MAX_KDC_RESPONSE_SIZE: usize = 1024 * 1024;

/// Send a message to a KDC via TCP (4-byte big-endian length prefix).
fn kdc_send_to(addr: &str, data: &[u8]) -> std::io::Result<Vec<u8>> {
    // TcpStream::connect is acceptable here — tests are #[ignore]'d and only
    // run when Docker KDC is explicitly started. The read timeout below
    // bounds the overall wait if the KDC is unresponsive.
    let mut stream = TcpStream::connect(addr)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let len_u32: u32 = data.len().try_into().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("KDC request too large: {} bytes", data.len()),
        )
    })?;
    let mut msg = Vec::with_capacity(4 + data.len());
    msg.extend_from_slice(&len_u32.to_be_bytes());
    msg.extend_from_slice(data);
    stream.write_all(&msg)?;
    stream.flush()?;
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    if resp_len > MAX_KDC_RESPONSE_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("KDC response too large: {resp_len} bytes (max {MAX_KDC_RESPONSE_SIZE})"),
        ));
    }
    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp)?;
    Ok(resp)
}

/// Send to the default (TEST.REALM) KDC.
fn kdc_send(data: &[u8]) -> std::io::Result<Vec<u8>> {
    kdc_send_to(KDC_ADDR, data)
}

/// Route a TGS request to the correct KDC based on realm.
fn kdc_send_for_realm(realm: &str, data: &[u8]) -> std::io::Result<Vec<u8>> {
    let addr = match realm {
        REALM => KDC_ADDR,
        OTHER_REALM => KDC_OTHER_ADDR,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("unexpected realm routing target: {realm}"),
            ));
        }
    };
    kdc_send_to(addr, data)
}

/// Drive the AS exchange to completion and return the TGT credential.
fn acquire_tgt(principal: &str, password: &str) -> Result<Credential, Krb5Error> {
    let config = AsExchangeConfig::new(PrincipalName::new_principal(principal), REALM);
    let mut exchange = AsExchange::new(config, password);
    let mut kdc_reply = Vec::new();
    for _ in 0..32 {
        match exchange.step(&kdc_reply)? {
            StepResult::SendToKdc { data, .. } | StepResult::RetryTcp { data, .. } => {
                kdc_reply = kdc_send(&data).map_err(Krb5Error::Transport)?;
            }
            StepResult::Complete => return exchange.credential().cloned(),
        }
    }
    Err(Krb5Error::ReplyValidation(
        "AS exchange did not complete within step limit",
    ))
}

/// Drive the TGS exchange to completion, routing to correct KDC per realm.
fn get_service_ticket(tgt: &Credential, target: PrincipalName) -> Result<Credential, Krb5Error> {
    let mut exchange = TgsExchange::new(tgt.clone(), target, TgsOptions::default());
    let mut kdc_reply = Vec::new();
    for _ in 0..32 {
        match exchange.step(&kdc_reply)? {
            TgsStepResult::SendToKdc { data, realm } | TgsStepResult::RetryTcp { data, realm } => {
                kdc_reply = kdc_send_for_realm(&realm, &data).map_err(Krb5Error::Transport)?;
            }
            TgsStepResult::Complete => return exchange.credential().cloned(),
        }
    }
    Err(Krb5Error::ReplyValidation(
        "TGS exchange did not complete within step limit",
    ))
}

/// Test: acquire a service ticket for HTTP/server.test.realm using a TGT.
///
/// Verifies the full AS exchange → TGS exchange flow:
/// 1. Get TGT via password authentication
/// 2. Use TGT to request service ticket
/// 3. Validate the service ticket metadata
#[test]
#[ignore = "requires KDC: docker compose -f docker-compose.test.yml up -d"]
fn test_get_service_ticket() {
    // Step 1: Acquire TGT
    let tgt = acquire_tgt("testuser", "testpassword").expect("AS exchange should succeed");
    assert_eq!(tgt.server.to_string(), "krbtgt/TEST.REALM");

    // Step 2: Request service ticket
    let target = PrincipalName::new_srv_inst("HTTP", "server.test.realm");
    let service_cred = get_service_ticket(&tgt, target).expect("TGS exchange should succeed");

    // Step 3: Validate service ticket
    assert_eq!(service_cred.server.to_string(), "HTTP/server.test.realm");
    assert_eq!(service_cred.srealm, REALM);
    assert_eq!(service_cred.client.to_string(), "testuser");
    assert_eq!(service_cred.crealm, REALM);
    // Session key should be AES-256 or AES-128
    assert!(
        service_cred.session_key.keytype == 18 || service_cred.session_key.keytype == 17,
        "unexpected session key type: {}",
        service_cred.session_key.keytype
    );
    assert!(!service_cred.session_key.key_bytes().is_empty());
    // Service session key should differ from TGT session key
    assert_ne!(
        service_cred.session_key.key_bytes(),
        tgt.session_key.key_bytes(),
        "service session key should differ from TGT session key"
    );
}

/// Test: requesting krbtgt/REALM via TGS exchange returns a valid TGT.
///
/// Verifies the TGS exchange can retrieve a krbtgt ticket (same pattern
/// used by clients before explicit TGT renewal via RENEW flag).
#[test]
#[ignore = "requires KDC: docker compose -f docker-compose.test.yml up -d"]
fn test_get_tgt_via_tgs() {
    let tgt = acquire_tgt("testuser", "testpassword").expect("AS exchange should succeed");

    let target = PrincipalName::new_srv_inst("krbtgt", REALM);
    let new_tgt = get_service_ticket(&tgt, target).expect("TGS exchange for krbtgt should succeed");

    assert_eq!(new_tgt.server.to_string(), "krbtgt/TEST.REALM");
    assert_eq!(new_tgt.srealm, REALM);
}

/// Test: requesting a ticket for an unknown service fails.
#[test]
#[ignore = "requires KDC: docker compose -f docker-compose.test.yml up -d"]
fn test_unknown_service_fails() {
    let tgt = acquire_tgt("testuser", "testpassword").expect("AS exchange should succeed");

    let target = PrincipalName::new_srv_inst("HTTP", "nonexistent.host.example.com");
    let result = get_service_ticket(&tgt, target);

    match result {
        Err(Krb5Error::KdcError(err)) => {
            assert_eq!(
                err.error_code,
                ErrorCode::SPrincipalUnknown as i32,
                "expected S_PRINCIPAL_UNKNOWN, got {}",
                err.error_code
            );
        }
        Err(other) => panic!("unexpected error: {other}"),
        Ok(_) => panic!("should have failed with unknown service principal"),
    }
}

/// Test: cross-realm service ticket — get a ticket for a service in OTHER.REALM.
///
/// MIT KDC does not return automatic referrals for host-based SPNs.
/// Instead, the client must explicitly acquire the cross-realm TGT first
/// (matching MIT krb5's actual behavior).
///
/// Flow:
/// 1. testuser@TEST.REALM gets TGT from TEST.REALM KDC
/// 2. TGS-REQ to TEST.REALM for krbtgt/OTHER.REALM → cross-realm TGT
/// 3. TGS-REQ to OTHER.REALM for HTTP/service.other.realm using cross-realm TGT
/// 4. OTHER.REALM returns service ticket
#[test]
#[ignore = "requires KDC: docker compose -f docker-compose.test.yml up -d"]
fn test_cross_realm_service_ticket() {
    // Step 1: Acquire TGT in home realm
    let tgt = acquire_tgt("testuser", "testpassword").expect("AS exchange should succeed");

    // Step 2: Explicitly request cross-realm TGT for OTHER.REALM
    let xrealm_target = PrincipalName::new_srv_inst("krbtgt", OTHER_REALM);
    let xrealm_tgt =
        get_service_ticket(&tgt, xrealm_target).expect("cross-realm TGT request should succeed");

    assert_eq!(xrealm_tgt.server.to_string(), "krbtgt/OTHER.REALM");
    assert_eq!(xrealm_tgt.srealm, REALM);

    // Step 3: Use cross-realm TGT to get service ticket from OTHER.REALM
    let target = PrincipalName::new_srv_inst("HTTP", "service.other.realm");
    let service_cred = get_service_ticket(&xrealm_tgt, target)
        .expect("service ticket via cross-realm TGT should succeed");

    // Validate
    assert_eq!(service_cred.server.to_string(), "HTTP/service.other.realm");
    assert_eq!(service_cred.srealm, OTHER_REALM);
    assert_eq!(service_cred.client.to_string(), "testuser");
    assert_eq!(service_cred.crealm, REALM);
    assert!(!service_cred.session_key.key_bytes().is_empty());
    // Service session key should differ from cross-realm TGT session key
    assert_ne!(
        service_cred.session_key.key_bytes(),
        xrealm_tgt.session_key.key_bytes(),
        "service session key should differ from cross-realm TGT session key"
    );
}
