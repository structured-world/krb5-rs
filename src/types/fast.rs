//! FAST extension types (RFC 6113).

use rasn::prelude::*;

use super::basic::*;
use super::preauth::PaData;
use super::primitives::*;

/// FAST options flags.
pub type FastOptions = BitString;

/// KrbFastReq — inner FAST request (RFC 6113 §5.4.2).
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct KrbFastReq {
    #[rasn(tag(explicit(context, 0)))]
    pub fast_options: FastOptions,
    #[rasn(tag(explicit(context, 1)))]
    pub padata: Vec<PaData>,
    #[rasn(tag(explicit(context, 2)))]
    pub req_body: super::kdc::KdcReqBody,
}

/// KrbFastArmor — armor type and value (RFC 6113 §5.4.1).
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct KrbFastArmor {
    #[rasn(tag(explicit(context, 0)))]
    pub armor_type: i32,
    #[rasn(tag(explicit(context, 1)))]
    pub armor_value: OctetString,
}

/// KrbFastArmoredReq — armored request wrapper (RFC 6113 §5.4.2).
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct KrbFastArmoredReq {
    #[rasn(tag(explicit(context, 0)))]
    pub armor: Option<KrbFastArmor>,
    #[rasn(tag(explicit(context, 1)))]
    pub req_checksum: Checksum,
    #[rasn(tag(explicit(context, 2)))]
    pub enc_fast_req: EncryptedData,
}

/// PA-FX-FAST-REQUEST — FAST request CHOICE (RFC 6113 §5.4.2).
#[derive(AsnType, Encode, Decode, Debug, Clone)]
#[rasn(choice)]
pub enum PaFxFastRequest {
    #[rasn(tag(explicit(context, 0)))]
    ArmoredData(KrbFastArmoredReq),
}

/// KrbFastResponse — inner FAST response (RFC 6113 §5.4.3).
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct KrbFastResponse {
    #[rasn(tag(explicit(context, 0)))]
    pub padata: Vec<PaData>,
    #[rasn(tag(explicit(context, 1)))]
    pub strengthen_key: Option<EncryptionKey>,
    #[rasn(tag(explicit(context, 2)))]
    pub finished: Option<KrbFastFinished>,
    #[rasn(tag(explicit(context, 3)))]
    pub nonce: u32,
}

/// KrbFastFinished — FAST completion proof (RFC 6113 §5.4.3).
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct KrbFastFinished {
    #[rasn(tag(explicit(context, 0)))]
    pub timestamp: KerberosTime,
    #[rasn(tag(explicit(context, 1)))]
    pub usec: i32,
    #[rasn(tag(explicit(context, 2)))]
    pub crealm: Realm,
    #[rasn(tag(explicit(context, 3)))]
    pub cname: PrincipalName,
    #[rasn(tag(explicit(context, 4)))]
    pub ticket_checksum: Checksum,
}

/// KrbFastArmoredRep — armored response wrapper (RFC 6113 §5.4.3).
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct KrbFastArmoredRep {
    #[rasn(tag(explicit(context, 0)))]
    pub enc_fast_rep: EncryptedData,
}

/// PA-FX-FAST-REPLY — FAST reply CHOICE (RFC 6113 §5.4.3).
#[derive(AsnType, Encode, Decode, Debug, Clone)]
#[rasn(choice)]
pub enum PaFxFastReply {
    #[rasn(tag(explicit(context, 0)))]
    ArmoredData(KrbFastArmoredRep),
}

/// KDC-PROXY-MESSAGE (MS-KKDCP §2.2.2).
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct KdcProxyMessage {
    #[rasn(tag(explicit(context, 0)))]
    pub kerb_message: OctetString,
    #[rasn(tag(explicit(context, 1)))]
    pub target_domain: Option<Realm>,
    #[rasn(tag(explicit(context, 2)))]
    pub dclocator_hint: Option<i32>,
}
