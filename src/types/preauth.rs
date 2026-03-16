//! Pre-authentication types (RFC 4120 §5.2.7, §7.5.2).

use rasn::prelude::*;

use super::primitives::*;

/// Pre-authentication data element (RFC 4120 §5.2.7).
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct PaData {
    #[rasn(tag(explicit(context, 1)))]
    pub padata_type: i32,
    #[rasn(tag(explicit(context, 2)))]
    pub padata_value: OctetString,
}

/// Encrypted timestamp for pre-authentication (RFC 4120 §5.2.7.2).
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct PaEncTsEnc {
    #[rasn(tag(explicit(context, 0)))]
    pub patimestamp: KerberosTime,
    #[rasn(tag(explicit(context, 1)))]
    pub pausec: Option<i32>,
}

/// PA-PAC-REQUEST (MS-KILE §2.2.3).
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct PaPacRequest {
    #[rasn(tag(explicit(context, 0)))]
    pub include_pac: bool,
}

/// PA-PAC-OPTIONS (MS-KILE §2.2.10).
///
/// Sent in TGS-REQ padata to request PAC-related options.
/// The `flags` field uses KerberosFlags encoding (BIT STRING).
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct PaPacOptions {
    #[rasn(tag(explicit(context, 0)))]
    pub flags: BitString,
}

/// ETYPE-INFO entry (legacy, RFC 4120 §5.2.7.4).
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct EtypeInfoEntry {
    #[rasn(tag(explicit(context, 0)))]
    pub etype: i32,
    #[rasn(tag(explicit(context, 1)))]
    pub salt: Option<OctetString>,
}

/// ETYPE-INFO2 entry (RFC 4120 §5.2.7.5).
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct EtypeInfo2Entry {
    #[rasn(tag(explicit(context, 0)))]
    pub etype: i32,
    #[rasn(tag(explicit(context, 1)))]
    pub salt: Option<KerberosString>,
    #[rasn(tag(explicit(context, 2)))]
    pub s2kparams: Option<OctetString>,
}
