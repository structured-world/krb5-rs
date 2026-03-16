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
//! use krb5_rs::types::{PrincipalName, AsReq};
//!
//! let principal = PrincipalName::new_principal("user");
//! assert_eq!(principal.to_string(), "user");
//! ```

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![warn(missing_docs)]

pub mod crypto;
pub mod error;
pub mod protocol;
pub mod types;

pub use error::Krb5Error;
