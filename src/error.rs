//! Error types for krb5-rs.

/// Errors that can occur during Kerberos operations.
#[derive(Debug, thiserror::Error)]
pub enum Krb5Error {
    /// KDC returned an error.
    #[error("KDC error {code}: {message}")]
    KdcError {
        /// Kerberos error code (RFC 4120 §7.5.9).
        code: i32,
        /// Human-readable message.
        message: String,
    },

    /// ASN.1 encoding/decoding error.
    #[error("ASN.1 error: {0}")]
    Asn1(String),

    /// Cryptographic operation failed.
    #[error("Crypto error: {0}")]
    Crypto(String),

    /// Network error (KDC unreachable).
    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),

    /// Ticket expired or not yet valid.
    #[error("Ticket expired")]
    TicketExpired,

    /// Pre-authentication required.
    #[error("Pre-authentication required")]
    PreauthRequired,

    /// GSSAPI error.
    #[error("GSSAPI error: {0}")]
    Gssapi(String),
}
