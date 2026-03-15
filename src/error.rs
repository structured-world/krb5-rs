//! Error types for krb5-rs.

use std::time::Duration;

use crate::types::KrbErrorMsg;

/// Errors that can occur during Kerberos operations.
#[derive(Debug, thiserror::Error)]
pub enum Krb5Error {
    /// KDC returned a protocol error (KRB-ERROR message).
    ///
    /// Use `.error_code()` and `.e_text()` for quick access,
    /// or match the inner `KrbErrorMsg` for full details.
    #[error("KDC error {}: {}", .0.error_code, .0.e_text.as_ref().map_or("(no message)", |s| core::str::from_utf8(s.as_ref()).unwrap_or("(invalid utf8)")))]
    KdcError(Box<KrbErrorMsg>),

    /// AS-REP/TGS-REP validation failed.
    #[error("reply validation failed: {0}")]
    ReplyValidation(&'static str),

    /// Decryption failed (wrong password or key).
    #[error("decryption failed")]
    DecryptionFailed,

    /// Clock skew between client and KDC exceeds tolerance.
    #[error("clock skew exceeds {max_skew:?}")]
    ClockSkew {
        /// Maximum allowed skew.
        max_skew: Duration,
    },

    /// Referral loop detected during TGS exchange.
    #[error("referral loop detected: visited {realm} twice")]
    ReferralLoop {
        /// Realm that was visited twice.
        realm: String,
    },

    /// Too many referral hops.
    #[error("exceeded maximum referral hops ({0})")]
    ReferralLimitExceeded(u32),

    /// Exceeded maximum pre-authentication retry count.
    #[error("exceeded maximum preauth retries ({0})")]
    PreauthLoopExceeded(u32),

    /// No mutually supported encryption type.
    #[error("no common encryption type with KDC")]
    NoCommonEtype,

    /// Unsupported encryption type encountered.
    #[error("unsupported etype {0}")]
    UnsupportedEtype(i32),

    /// ASN.1 encoding/decoding failure.
    #[error("ASN.1 decode error: {0}")]
    Asn1Decode(#[from] rasn::error::DecodeError),

    /// ASN.1 encoding failure.
    #[error("ASN.1 encode error: {0}")]
    Asn1Encode(#[from] rasn::error::EncodeError),

    /// Cryptographic operation failed.
    #[error("crypto error: {0}")]
    Crypto(String),

    /// Network/transport error.
    #[error("transport error: {0}")]
    Transport(#[from] std::io::Error),
}

impl Krb5Error {
    /// Create a KDC error from a KRB-ERROR message.
    pub fn from_error_msg(msg: KrbErrorMsg) -> Self {
        Self::KdcError(Box::new(msg))
    }
}
