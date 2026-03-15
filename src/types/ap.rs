//! AP exchange types — AP-REQ, AP-REP, Authenticator (RFC 4120 §5.5).

use rasn::prelude::*;

use super::basic::*;
use super::primitives::*;
use super::ticket::Ticket;

/// AP-REQ (APPLICATION 14) — RFC 4120 §5.5.1.
#[derive(AsnType, Encode, Decode, Debug, Clone)]
#[rasn(tag(explicit(application, 14)))]
pub struct ApReq {
    #[rasn(tag(explicit(context, 0)))]
    pub pvno: i32,
    #[rasn(tag(explicit(context, 1)))]
    pub msg_type: i32,
    #[rasn(tag(explicit(context, 2)))]
    pub ap_options: BitString,
    #[rasn(tag(explicit(context, 3)))]
    pub ticket: Ticket,
    #[rasn(tag(explicit(context, 4)))]
    pub authenticator: EncryptedData,
}

/// AP-REP (APPLICATION 15) — RFC 4120 §5.5.2.
#[derive(AsnType, Encode, Decode, Debug, Clone)]
#[rasn(tag(explicit(application, 15)))]
pub struct ApRep {
    #[rasn(tag(explicit(context, 0)))]
    pub pvno: i32,
    #[rasn(tag(explicit(context, 1)))]
    pub msg_type: i32,
    #[rasn(tag(explicit(context, 2)))]
    pub enc_part: EncryptedData,
}

/// Encrypted part of AP-REP (APPLICATION 27) — RFC 4120 §5.5.2.
#[derive(AsnType, Encode, Decode, Debug, Clone)]
#[rasn(tag(explicit(application, 27)))]
pub struct EncApRepPart {
    #[rasn(tag(explicit(context, 0)))]
    pub ctime: KerberosTime,
    #[rasn(tag(explicit(context, 1)))]
    pub cusec: i32,
    #[rasn(tag(explicit(context, 2)))]
    pub subkey: Option<EncryptionKey>,
    #[rasn(tag(explicit(context, 3)))]
    pub seq_number: Option<u32>,
}

/// Authenticator (APPLICATION 2) — RFC 4120 §5.5.1.
#[derive(AsnType, Encode, Decode, Debug, Clone)]
#[rasn(tag(explicit(application, 2)))]
pub struct Authenticator {
    #[rasn(tag(explicit(context, 0)))]
    pub authenticator_vno: i32,
    #[rasn(tag(explicit(context, 1)))]
    pub crealm: Realm,
    #[rasn(tag(explicit(context, 2)))]
    pub cname: PrincipalName,
    #[rasn(tag(explicit(context, 3)))]
    pub cksum: Option<Checksum>,
    #[rasn(tag(explicit(context, 4)))]
    pub cusec: i32,
    #[rasn(tag(explicit(context, 5)))]
    pub ctime: KerberosTime,
    #[rasn(tag(explicit(context, 6)))]
    pub subkey: Option<EncryptionKey>,
    #[rasn(tag(explicit(context, 7)))]
    pub seq_number: Option<u32>,
    #[rasn(tag(explicit(context, 8)))]
    pub authorization_data: Option<Vec<AuthorizationDataElement>>,
}
