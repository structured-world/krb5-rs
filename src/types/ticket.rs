//! Ticket types (RFC 4120 §5.3).

use rasn::prelude::*;

use super::basic::*;
use super::flags::{KerberosFlags, TicketFlags};
use super::primitives::*;

/// Ticket (APPLICATION 1) — RFC 4120 §5.3.
#[derive(AsnType, Encode, Decode, Debug, Clone)]
#[rasn(tag(explicit(application, 1)))]
pub struct Ticket {
    #[rasn(tag(explicit(context, 0)))]
    pub tkt_vno: i32,
    #[rasn(tag(explicit(context, 1)))]
    pub realm: Realm,
    #[rasn(tag(explicit(context, 2)))]
    pub sname: PrincipalName,
    #[rasn(tag(explicit(context, 3)))]
    pub enc_part: EncryptedData,
}

/// Decrypted ticket contents (APPLICATION 3) — RFC 4120 §5.3.
#[derive(AsnType, Encode, Decode, Debug, Clone)]
#[rasn(tag(explicit(application, 3)))]
pub struct EncTicketPart {
    #[rasn(tag(explicit(context, 0)))]
    pub flags: KerberosFlags<TicketFlags>,
    #[rasn(tag(explicit(context, 1)))]
    pub key: EncryptionKey,
    #[rasn(tag(explicit(context, 2)))]
    pub crealm: Realm,
    #[rasn(tag(explicit(context, 3)))]
    pub cname: PrincipalName,
    #[rasn(tag(explicit(context, 4)))]
    pub transited: TransitedEncoding,
    #[rasn(tag(explicit(context, 5)))]
    pub authtime: KerberosTime,
    #[rasn(tag(explicit(context, 6)))]
    pub starttime: Option<KerberosTime>,
    #[rasn(tag(explicit(context, 7)))]
    pub endtime: KerberosTime,
    #[rasn(tag(explicit(context, 8)))]
    pub renew_till: Option<KerberosTime>,
    #[rasn(tag(explicit(context, 9)))]
    pub caddr: Option<Vec<HostAddress>>,
    #[rasn(tag(explicit(context, 10)))]
    pub authorization_data: Option<Vec<AuthorizationDataElement>>,
}
