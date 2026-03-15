//! Kerberos bit flag types (RFC 4120 §5.2.8).
//!
//! These types provide named constants for the bit positions
//! used in KDCOptions, TicketFlags, and APOptions BitStrings.

use bitflags::bitflags;

bitflags! {
    /// KDC options flags (RFC 4120 §5.4.1).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct KdcOptions: u32 {
        const RESERVED          = 1 << 31; // bit 0
        const FORWARDABLE       = 1 << 30; // bit 1
        const FORWARDED         = 1 << 29; // bit 2
        const PROXIABLE         = 1 << 28; // bit 3
        const PROXY             = 1 << 27; // bit 4
        const ALLOW_POSTDATE    = 1 << 26; // bit 5
        const POSTDATED         = 1 << 25; // bit 6
        // bit 7 unused
        const RENEWABLE         = 1 << 23; // bit 8
        // bits 9-14 unused
        const CANONICALIZE      = 1 << 16; // bit 15
        const REQUEST_ANONYMOUS = 1 << 15; // bit 16
        // bits 17-25 unused
        const DISABLE_TRANSITED_CHECK = 1 << 5; // bit 26
        const RENEWABLE_OK      = 1 << 4;  // bit 27
        const ENC_TKT_IN_SKEY   = 1 << 3;  // bit 28
        // bit 29 unused
        const RENEW             = 1 << 1;  // bit 30
        const VALIDATE          = 1 << 0;  // bit 31
    }
}

bitflags! {
    /// Ticket flags (RFC 4120 §5.3).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct TicketFlags: u32 {
        const RESERVED            = 1 << 31; // bit 0
        const FORWARDABLE         = 1 << 30; // bit 1
        const FORWARDED           = 1 << 29; // bit 2
        const PROXIABLE           = 1 << 28; // bit 3
        const PROXY               = 1 << 27; // bit 4
        const MAY_POSTDATE        = 1 << 26; // bit 5
        const POSTDATED           = 1 << 25; // bit 6
        const INVALID             = 1 << 24; // bit 7
        const RENEWABLE           = 1 << 23; // bit 8
        const INITIAL             = 1 << 22; // bit 9
        const PRE_AUTHENT         = 1 << 21; // bit 10
        const HW_AUTHENT          = 1 << 20; // bit 11
        const TRANSITED_POLICY_CHECKED = 1 << 19; // bit 12
        const OK_AS_DELEGATE      = 1 << 18; // bit 13
        // bit 14 unused
        const ENC_PA_REP          = 1 << 16; // bit 15
        const ANONYMOUS           = 1 << 15; // bit 16
    }
}

bitflags! {
    /// AP options flags (RFC 4120 §5.5.1).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ApOptions: u32 {
        const RESERVED        = 1 << 31; // bit 0
        const USE_SESSION_KEY = 1 << 30; // bit 1
        const MUTUAL_REQUIRED = 1 << 29; // bit 2
    }
}

impl KdcOptions {
    /// Convert to a 4-byte big-endian byte array suitable for ASN.1 BitString.
    pub fn to_bytes(&self) -> [u8; 4] {
        self.bits().to_be_bytes()
    }

    /// Parse from a 4-byte big-endian byte array (from ASN.1 BitString).
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut buf = [0u8; 4];
        let len = bytes.len().min(4);
        buf[..len].copy_from_slice(&bytes[..len]);
        Self::from_bits_truncate(u32::from_be_bytes(buf))
    }
}

impl TicketFlags {
    /// Convert to a 4-byte big-endian byte array suitable for ASN.1 BitString.
    pub fn to_bytes(&self) -> [u8; 4] {
        self.bits().to_be_bytes()
    }

    /// Parse from a 4-byte big-endian byte array (from ASN.1 BitString).
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut buf = [0u8; 4];
        let len = bytes.len().min(4);
        buf[..len].copy_from_slice(&bytes[..len]);
        Self::from_bits_truncate(u32::from_be_bytes(buf))
    }
}

impl ApOptions {
    /// Convert to a 4-byte big-endian byte array suitable for ASN.1 BitString.
    pub fn to_bytes(&self) -> [u8; 4] {
        self.bits().to_be_bytes()
    }

    /// Parse from a 4-byte big-endian byte array (from ASN.1 BitString).
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut buf = [0u8; 4];
        let len = bytes.len().min(4);
        buf[..len].copy_from_slice(&bytes[..len]);
        Self::from_bits_truncate(u32::from_be_bytes(buf))
    }
}
