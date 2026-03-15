//! KDC exchange types — AS-REQ, AS-REP, TGS-REQ, TGS-REP (RFC 4120 §5.4).

use rasn::prelude::*;

use super::basic::*;
use super::preauth::PaData;
use super::primitives::*;
use super::ticket::Ticket;

/// KDC request body (RFC 4120 §5.4.1).
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct KdcReqBody {
    #[rasn(tag(explicit(context, 0)))]
    pub kdc_options: BitString,
    #[rasn(tag(explicit(context, 1)))]
    pub cname: Option<PrincipalName>,
    #[rasn(tag(explicit(context, 2)))]
    pub realm: Realm,
    #[rasn(tag(explicit(context, 3)))]
    pub sname: Option<PrincipalName>,
    #[rasn(tag(explicit(context, 4)))]
    pub from: Option<KerberosTime>,
    #[rasn(tag(explicit(context, 5)))]
    pub till: Option<KerberosTime>,
    #[rasn(tag(explicit(context, 6)))]
    pub rtime: Option<KerberosTime>,
    #[rasn(tag(explicit(context, 7)))]
    pub nonce: u32,
    #[rasn(tag(explicit(context, 8)))]
    pub etype: Vec<i32>,
    #[rasn(tag(explicit(context, 9)))]
    pub addresses: Option<Vec<HostAddress>>,
    #[rasn(tag(explicit(context, 10)))]
    pub enc_authorization_data: Option<EncryptedData>,
    #[rasn(tag(explicit(context, 11)))]
    pub additional_tickets: Option<Vec<Ticket>>,
}

/// KDC request (RFC 4120 §5.4.1).
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct KdcReq {
    #[rasn(tag(explicit(context, 1)))]
    pub pvno: i32,
    #[rasn(tag(explicit(context, 2)))]
    pub msg_type: i32,
    #[rasn(tag(explicit(context, 3)))]
    pub padata: Option<Vec<PaData>>,
    #[rasn(tag(explicit(context, 4)))]
    pub req_body: KdcReqBody,
}

/// AS-REQ (APPLICATION 10) — RFC 4120 §5.4.1.
#[derive(AsnType, Encode, Decode, Debug, Clone)]
#[rasn(delegate, tag(explicit(application, 10)))]
pub struct AsReq(pub KdcReq);

/// TGS-REQ (APPLICATION 12) — RFC 4120 §5.4.1.
#[derive(AsnType, Encode, Decode, Debug, Clone)]
#[rasn(delegate, tag(explicit(application, 12)))]
pub struct TgsReq(pub KdcReq);

/// KDC reply (RFC 4120 §5.4.2).
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct KdcRep {
    #[rasn(tag(explicit(context, 0)))]
    pub pvno: i32,
    #[rasn(tag(explicit(context, 1)))]
    pub msg_type: i32,
    #[rasn(tag(explicit(context, 2)))]
    pub padata: Option<Vec<PaData>>,
    #[rasn(tag(explicit(context, 3)))]
    pub crealm: Realm,
    #[rasn(tag(explicit(context, 4)))]
    pub cname: PrincipalName,
    #[rasn(tag(explicit(context, 5)))]
    pub ticket: Ticket,
    #[rasn(tag(explicit(context, 6)))]
    pub enc_part: EncryptedData,
}

/// AS-REP (APPLICATION 11) — RFC 4120 §5.4.2.
#[derive(AsnType, Encode, Decode, Debug, Clone)]
#[rasn(delegate, tag(explicit(application, 11)))]
pub struct AsRep(pub KdcRep);

/// TGS-REP (APPLICATION 13) — RFC 4120 §5.4.2.
#[derive(AsnType, Encode, Decode, Debug, Clone)]
#[rasn(delegate, tag(explicit(application, 13)))]
pub struct TgsRep(pub KdcRep);

/// Encrypted part of KDC reply (RFC 4120 §5.4.2).
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct EncKdcRepPart {
    #[rasn(tag(explicit(context, 0)))]
    pub key: EncryptionKey,
    #[rasn(tag(explicit(context, 1)))]
    pub last_req: Vec<LastReqEntry>,
    #[rasn(tag(explicit(context, 2)))]
    pub nonce: u32,
    #[rasn(tag(explicit(context, 3)))]
    pub key_expiration: Option<KerberosTime>,
    #[rasn(tag(explicit(context, 4)))]
    pub flags: BitString,
    #[rasn(tag(explicit(context, 5)))]
    pub authtime: KerberosTime,
    #[rasn(tag(explicit(context, 6)))]
    pub starttime: Option<KerberosTime>,
    #[rasn(tag(explicit(context, 7)))]
    pub endtime: KerberosTime,
    #[rasn(tag(explicit(context, 8)))]
    pub renew_till: Option<KerberosTime>,
    #[rasn(tag(explicit(context, 9)))]
    pub srealm: Realm,
    #[rasn(tag(explicit(context, 10)))]
    pub sname: PrincipalName,
    #[rasn(tag(explicit(context, 11)))]
    pub caddr: Option<Vec<HostAddress>>,
    #[rasn(tag(explicit(context, 12)))]
    pub encrypted_pa_data: Option<Vec<PaData>>,
}

/// EncASRepPart (APPLICATION 25) — RFC 4120 §5.4.2.
#[derive(AsnType, Encode, Decode, Debug, Clone)]
#[rasn(delegate, tag(explicit(application, 25)))]
pub struct EncAsRepPart(pub EncKdcRepPart);

/// EncTGSRepPart (APPLICATION 26) — RFC 4120 §5.4.2.
#[derive(AsnType, Encode, Decode, Debug, Clone)]
#[rasn(delegate, tag(explicit(application, 26)))]
pub struct EncTgsRepPart(pub EncKdcRepPart);
