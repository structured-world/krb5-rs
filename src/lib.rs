//! # krb5-rs — Pure Rust Kerberos V5
//!
//! No C FFI, no system krb5 dependency. GSSAPI, SPNEGO, PKINIT.
//!
//! ## Protocols
//!
//! - **RFC 4120** — Kerberos V5 core
//! - **RFC 4121** — GSSAPI mechanism
//! - **RFC 3961/3962** — Encryption specs + AES
//! - **RFC 4556** — PKINIT
//! - **RFC 6113** — FAST pre-authentication
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use krb5_rs::client::KerberosClient;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let client = KerberosClient::new("EXAMPLE.COM", "kdc.example.com:88").await?;
//! let tgt = client.get_tgt("user", "password").await?;
//! let ticket = client.get_service_ticket(&tgt, "HTTP/web.example.com").await?;
//! # Ok(())
//! # }
//! ```

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![warn(missing_docs)]

pub mod error;

#[cfg(feature = "client")]
pub mod client;

pub mod crypto;
pub mod types;

#[cfg(feature = "gssapi")]
pub mod gssapi;

pub use error::Krb5Error;
