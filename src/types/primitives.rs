//! Primitive type aliases for Kerberos V5 (RFC 4120).

use rasn::prelude::*;

/// Realm name — a GeneralString representing a Kerberos realm.
pub type Realm = GeneralString;

/// Kerberos string — GeneralString (UTF-8 in practice).
pub type KerberosString = GeneralString;

/// Kerberos timestamp — GeneralizedTime (UTC, "Z" suffix).
pub type KerberosTime = GeneralizedTime;
