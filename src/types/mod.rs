//! Kerberos V5 ASN.1 types (RFC 4120, RFC 6113).
//!
//! All types are defined manually from the Heimdal `krb5.asn1` module
//! using `rasn` derive macros for DER encoding/decoding.
//!
//! Struct fields map directly to RFC 4120 Appendix A field definitions
//! and are self-documenting via their names.
#![allow(missing_docs)]

mod ap;
mod basic;
mod enums;
mod error_msg;
mod fast;
mod flags;
mod kdc;
mod preauth;
mod primitives;
mod safe_priv_cred;
mod ticket;

pub use ap::*;
pub use basic::*;
pub use enums::*;
pub use error_msg::*;
pub use fast::*;
pub use flags::*;
pub use kdc::*;
pub use preauth::*;
pub use primitives::*;
pub use safe_priv_cred::*;
pub use ticket::*;

// --- Composite type aliases (RFC 4120 §5.2) ---

/// SEQUENCE OF HostAddress (RFC 4120 §5.2.5).
pub type HostAddresses = Vec<HostAddress>;

/// AuthorizationData — SEQUENCE OF AuthorizationDataElement (RFC 4120 §5.2.6).
pub type AuthorizationData = Vec<AuthorizationDataElement>;

/// METHOD-DATA — SEQUENCE OF PA-DATA (RFC 4120 §5.2.7).
pub type MethodData = Vec<PaData>;

/// ETYPE-INFO — SEQUENCE OF ETYPE-INFO-ENTRY (RFC 4120 §5.2.7.4).
pub type EtypeInfo = Vec<EtypeInfoEntry>;

/// ETYPE-INFO2 — SEQUENCE OF ETYPE-INFO2-ENTRY (RFC 4120 §5.2.7.5).
pub type EtypeInfo2 = Vec<EtypeInfo2Entry>;
