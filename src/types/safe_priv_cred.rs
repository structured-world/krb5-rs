//! KRB-SAFE, KRB-PRIV, KRB-CRED types (RFC 4120 §5.6, §5.7, §5.8).

use rasn::prelude::*;

use super::basic::*;
use super::flags::{KerberosFlags, TicketFlags};
use super::primitives::*;
use super::ticket::Ticket;

/// KRB-SAFE-BODY (RFC 4120 §5.6.1).
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct KrbSafeBody {
    #[rasn(tag(explicit(context, 0)))]
    pub user_data: OctetString,
    #[rasn(tag(explicit(context, 1)))]
    pub timestamp: Option<KerberosTime>,
    #[rasn(tag(explicit(context, 2)))]
    pub usec: Option<i32>,
    #[rasn(tag(explicit(context, 3)))]
    pub seq_number: Option<u32>,
    #[rasn(tag(explicit(context, 4)))]
    pub s_address: HostAddress,
    #[rasn(tag(explicit(context, 5)))]
    pub r_address: Option<HostAddress>,
}

/// KRB-SAFE (APPLICATION 20) — RFC 4120 §5.6.1.
#[derive(AsnType, Encode, Decode, Debug, Clone)]
#[rasn(tag(explicit(application, 20)))]
pub struct KrbSafe {
    #[rasn(tag(explicit(context, 0)))]
    pub pvno: i32,
    #[rasn(tag(explicit(context, 1)))]
    pub msg_type: i32,
    #[rasn(tag(explicit(context, 2)))]
    pub safe_body: KrbSafeBody,
    #[rasn(tag(explicit(context, 3)))]
    pub cksum: Checksum,
}

/// KRB-PRIV (APPLICATION 21) — RFC 4120 §5.7.1.
#[derive(AsnType, Encode, Decode, Debug, Clone)]
#[rasn(tag(explicit(application, 21)))]
pub struct KrbPriv {
    #[rasn(tag(explicit(context, 0)))]
    pub pvno: i32,
    #[rasn(tag(explicit(context, 1)))]
    pub msg_type: i32,
    #[rasn(tag(explicit(context, 3)))]
    pub enc_part: EncryptedData,
}

/// Encrypted part of KRB-PRIV (APPLICATION 28) — RFC 4120 §5.7.1.
#[derive(AsnType, Encode, Decode, Debug, Clone)]
#[rasn(tag(explicit(application, 28)))]
pub struct EncKrbPrivPart {
    #[rasn(tag(explicit(context, 0)))]
    pub user_data: OctetString,
    #[rasn(tag(explicit(context, 1)))]
    pub timestamp: Option<KerberosTime>,
    #[rasn(tag(explicit(context, 2)))]
    pub usec: Option<i32>,
    #[rasn(tag(explicit(context, 3)))]
    pub seq_number: Option<u32>,
    #[rasn(tag(explicit(context, 4)))]
    pub s_address: HostAddress,
    #[rasn(tag(explicit(context, 5)))]
    pub r_address: Option<HostAddress>,
}

/// KRB-CRED (APPLICATION 22) — RFC 4120 §5.8.1.
#[derive(AsnType, Encode, Decode, Debug, Clone)]
#[rasn(tag(explicit(application, 22)))]
pub struct KrbCred {
    #[rasn(tag(explicit(context, 0)))]
    pub pvno: i32,
    #[rasn(tag(explicit(context, 1)))]
    pub msg_type: i32,
    #[rasn(tag(explicit(context, 2)))]
    pub tickets: Vec<Ticket>,
    #[rasn(tag(explicit(context, 3)))]
    pub enc_part: EncryptedData,
}

/// Credential info in KRB-CRED (RFC 4120 §5.8.1).
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct KrbCredInfo {
    #[rasn(tag(explicit(context, 0)))]
    pub key: EncryptionKey,
    #[rasn(tag(explicit(context, 1)))]
    pub prealm: Option<Realm>,
    #[rasn(tag(explicit(context, 2)))]
    pub pname: Option<PrincipalName>,
    #[rasn(tag(explicit(context, 3)))]
    pub flags: Option<KerberosFlags<TicketFlags>>,
    #[rasn(tag(explicit(context, 4)))]
    pub authtime: Option<KerberosTime>,
    #[rasn(tag(explicit(context, 5)))]
    pub starttime: Option<KerberosTime>,
    #[rasn(tag(explicit(context, 6)))]
    pub endtime: Option<KerberosTime>,
    #[rasn(tag(explicit(context, 7)))]
    pub renew_till: Option<KerberosTime>,
    #[rasn(tag(explicit(context, 8)))]
    pub srealm: Option<Realm>,
    #[rasn(tag(explicit(context, 9)))]
    pub sname: Option<PrincipalName>,
    #[rasn(tag(explicit(context, 10)))]
    pub caddr: Option<Vec<HostAddress>>,
}

/// Encrypted part of KRB-CRED (APPLICATION 29) — RFC 4120 §5.8.1.
#[derive(AsnType, Encode, Decode, Debug, Clone)]
#[rasn(tag(explicit(application, 29)))]
pub struct EncKrbCredPart {
    #[rasn(tag(explicit(context, 0)))]
    pub ticket_info: Vec<KrbCredInfo>,
    #[rasn(tag(explicit(context, 1)))]
    pub nonce: Option<u32>,
    #[rasn(tag(explicit(context, 2)))]
    pub timestamp: Option<KerberosTime>,
    #[rasn(tag(explicit(context, 3)))]
    pub usec: Option<i32>,
    #[rasn(tag(explicit(context, 4)))]
    pub s_address: Option<HostAddress>,
    #[rasn(tag(explicit(context, 5)))]
    pub r_address: Option<HostAddress>,
}
