//! Kerberos bit flag types (RFC 4120 §5.2.8).
//!
//! Provides typed wrappers around ASN.1 BIT STRING fields for KDCOptions,
//! TicketFlags, and APOptions. The [`KerberosFlags<T>`] newtype ensures
//! compile-time type safety while remaining wire-compatible with rasn's
//! BIT STRING encoding.

use core::fmt;
use core::ops::{Deref, DerefMut};

use bitflags::bitflags;
use rasn::prelude::*;

// ---------------------------------------------------------------------------
// Trait: Flags — conversion between bitflags and 4-byte big-endian wire form
// ---------------------------------------------------------------------------

/// Trait implemented by Kerberos bitflag types that can round-trip through
/// a 4-byte big-endian representation used in ASN.1 BIT STRINGs.
pub trait Flags: Copy + fmt::Debug {
    /// Encode the flags as a 4-byte big-endian array.
    fn to_bytes(&self) -> [u8; 4];

    /// Decode flags from a big-endian byte slice (≤ 4 bytes, zero-padded).
    fn from_bytes(bytes: &[u8]) -> Self;

    /// Return the empty (all-zero) flag set.
    fn empty() -> Self;
}

// ---------------------------------------------------------------------------
// KerberosFlags<T> — ASN.1 BIT STRING newtype with typed flag access
// ---------------------------------------------------------------------------

/// ASN.1 BIT STRING wrapper that carries a typed Kerberos flag set.
///
/// Stores the flags in their native bitflags representation and converts
/// to/from `BitString` only during ASN.1 encoding/decoding.  Implements
/// [`Deref`] and [`DerefMut`] to `T`, so callers can use the bitflags API
/// directly (e.g. `body.kdc_options.contains(KdcOptions::FORWARDABLE)`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KerberosFlags<T: Flags> {
    flags: T,
}

impl<T: Flags> KerberosFlags<T> {
    /// Wrap a typed flag value.
    pub fn new(flags: T) -> Self {
        Self { flags }
    }

    /// Return the inner flags value.
    pub fn into_inner(self) -> T {
        self.flags
    }
}

impl<T: Flags> fmt::Debug for KerberosFlags<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.flags.fmt(f)
    }
}

// --- Deref / DerefMut to the inner bitflags type ---

impl<T: Flags> Deref for KerberosFlags<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.flags
    }
}

impl<T: Flags> DerefMut for KerberosFlags<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.flags
    }
}

// --- From conversions ---

impl<T: Flags> From<T> for KerberosFlags<T> {
    fn from(flags: T) -> Self {
        Self { flags }
    }
}

impl<T: Flags> Default for KerberosFlags<T> {
    fn default() -> Self {
        Self { flags: T::empty() }
    }
}

// --- rasn ASN.1 implementation (BIT STRING on the wire) ---

// TAG + IDENTIFIER follow the same pattern as rasn's own BitString impl
// (see rasn-0.28 types/strings/bit.rs). TAG_TREE has a default based on TAG.
impl<T: Flags> AsnType for KerberosFlags<T> {
    const TAG: Tag = Tag::BIT_STRING;
    const IDENTIFIER: Identifier = Identifier::BIT_STRING;
}

impl<T: Flags> Decode for KerberosFlags<T> {
    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        let bits: BitString =
            BitString::decode_with_tag_and_constraints(decoder, tag, constraints)?;
        let raw = bits.as_raw_slice();
        Ok(Self {
            flags: T::from_bytes(raw),
        })
    }
}

impl<T: Flags> Encode for KerberosFlags<T> {
    fn encode_with_tag_and_constraints<'b, E: Encoder<'b>>(
        &self,
        encoder: &mut E,
        tag: Tag,
        constraints: Constraints,
        identifier: Identifier,
    ) -> Result<(), E::Error> {
        let bytes = self.flags.to_bytes();
        let bits = BitString::from_slice(&bytes);
        bits.encode_with_tag_and_constraints(encoder, tag, constraints, identifier)
    }
}

// ---------------------------------------------------------------------------
// Bitflags definitions
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Flags trait implementations
// ---------------------------------------------------------------------------

macro_rules! impl_flags {
    ($ty:ty) => {
        impl Flags for $ty {
            fn to_bytes(&self) -> [u8; 4] {
                self.bits().to_be_bytes()
            }

            fn from_bytes(bytes: &[u8]) -> Self {
                let mut buf = [0u8; 4];
                let len = bytes.len().min(4);
                buf[..len].copy_from_slice(&bytes[..len]);
                Self::from_bits_truncate(u32::from_be_bytes(buf))
            }

            fn empty() -> Self {
                <$ty>::empty()
            }
        }
    };
}

impl_flags!(KdcOptions);
impl_flags!(TicketFlags);
impl_flags!(ApOptions);
