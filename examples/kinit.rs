//! Simple kinit example — acquire a TGT from a KDC.
//!
//! Usage: cargo run --example kinit
//! Env vars: KDC_ADDR, KRB5_PRINCIPAL, KRB5_REALM, KRB5_PASSWORD

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use krb5_rs::protocol::{AsExchange, AsExchangeConfig, StepResult};
use krb5_rs::types::PrincipalName;

/// Maximum acceptable KDC response size (1 MiB).
const MAX_KDC_RESPONSE_SIZE: usize = 1024 * 1024;

fn main() {
    let kdc_addr = std::env::var("KDC_ADDR").unwrap_or_else(|_| "127.0.0.1:10188".to_string());
    let principal = std::env::var("KRB5_PRINCIPAL").unwrap_or_else(|_| "testuser".to_string());
    let realm = std::env::var("KRB5_REALM").unwrap_or_else(|_| "TEST.REALM".to_string());
    let password = std::env::var("KRB5_PASSWORD").unwrap_or_else(|_| "testpassword".to_string());

    println!("Connecting to KDC at {kdc_addr}...");
    println!("Principal: {principal}@{realm}");

    let config = AsExchangeConfig::new(PrincipalName::new_principal(&principal), &realm);
    let mut exchange = AsExchange::new(config, &password);

    let mut kdc_reply = Vec::new();
    let mut round = 0;
    loop {
        round += 1;
        match exchange.step(&kdc_reply) {
            Ok(
                StepResult::SendToKdc { data, realm: r } | StepResult::RetryTcp { data, realm: r },
            ) => {
                println!("Round {round}: sending {} bytes to {r}", data.len());
                kdc_reply = tcp_send(&kdc_addr, &data).expect("TCP send failed");
                println!("Round {round}: received {} bytes", kdc_reply.len());
            }
            Ok(StepResult::Complete) => {
                let cred = exchange.credential().expect("no credential");
                println!("\nSuccess!");
                println!("  Client: {}", cred.client);
                println!("  Realm:  {}", cred.crealm);
                println!("  Server: {}", cred.server);
                println!("  Key type: {}", cred.session_key.keytype);
                break;
            }
            Err(e) => {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
    }
}

fn tcp_send(addr: &str, data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(addr)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut msg = Vec::with_capacity(4 + data.len());
    msg.extend_from_slice(&(data.len() as u32).to_be_bytes());
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
