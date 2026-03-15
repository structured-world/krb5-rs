//! Kerberos enumeration types (named integer constants).

/// Principal name types (RFC 4120 §6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum NameType {
    /// Name type not known.
    Unknown = 0,
    /// Just the name of the principal.
    Principal = 1,
    /// Service and other unique instance (krbtgt).
    SrvInst = 2,
    /// Service with host name as instance.
    SrvHst = 3,
    /// Service with host as remaining components.
    SrvXhst = 4,
    /// Unique ID.
    Uid = 5,
    /// X.500 distinguished name (PKINIT).
    X500Principal = 6,
    /// SMTP name.
    SmtpName = 7,
    /// Enterprise principal (UPN).
    Enterprise = 10,
    /// Well-known principal.
    Wellknown = 11,
    /// Service with domain name.
    SrvHstDomain = 12,
}

impl TryFrom<i32> for NameType {
    type Error = i32;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Unknown),
            1 => Ok(Self::Principal),
            2 => Ok(Self::SrvInst),
            3 => Ok(Self::SrvHst),
            4 => Ok(Self::SrvXhst),
            5 => Ok(Self::Uid),
            6 => Ok(Self::X500Principal),
            7 => Ok(Self::SmtpName),
            10 => Ok(Self::Enterprise),
            11 => Ok(Self::Wellknown),
            12 => Ok(Self::SrvHstDomain),
            other => Err(other),
        }
    }
}

/// Message types (RFC 4120 §7.5.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum MessageType {
    AsReq = 10,
    AsRep = 11,
    TgsReq = 12,
    TgsRep = 13,
    ApReq = 14,
    ApRep = 15,
    KrbSafe = 20,
    KrbPriv = 21,
    KrbCred = 22,
    KrbError = 30,
}

impl TryFrom<i32> for MessageType {
    type Error = i32;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            10 => Ok(Self::AsReq),
            11 => Ok(Self::AsRep),
            12 => Ok(Self::TgsReq),
            13 => Ok(Self::TgsRep),
            14 => Ok(Self::ApReq),
            15 => Ok(Self::ApRep),
            20 => Ok(Self::KrbSafe),
            21 => Ok(Self::KrbPriv),
            22 => Ok(Self::KrbCred),
            30 => Ok(Self::KrbError),
            other => Err(other),
        }
    }
}

/// Pre-authentication data types (RFC 4120 §7.5.2, RFC 6113).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum PaDataType {
    None = 0,
    TgsReq = 1,
    EncTimestamp = 2,
    PwSalt = 3,
    EtypeInfo = 11,
    EtypeInfo2 = 19,
    PaPacRequest = 128,
    FxCookie = 133,
    FxFast = 136,
    EncryptedChallenge = 138,
    ReqEncPaRep = 149,
    SupportedEtypes = 165,
    PacOptions = 167,
}

impl TryFrom<i32> for PaDataType {
    type Error = i32;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::TgsReq),
            2 => Ok(Self::EncTimestamp),
            3 => Ok(Self::PwSalt),
            11 => Ok(Self::EtypeInfo),
            19 => Ok(Self::EtypeInfo2),
            128 => Ok(Self::PaPacRequest),
            133 => Ok(Self::FxCookie),
            136 => Ok(Self::FxFast),
            138 => Ok(Self::EncryptedChallenge),
            149 => Ok(Self::ReqEncPaRep),
            165 => Ok(Self::SupportedEtypes),
            167 => Ok(Self::PacOptions),
            other => Err(other),
        }
    }
}

/// Encryption type identifiers (RFC 3961, RFC 3962, RFC 4757).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum EncType {
    Null = 0,
    DesCbcCrc = 1,
    DesCbcMd5 = 3,
    Des3CbcSha1 = 16,
    Aes128CtsHmacSha196 = 17,
    Aes256CtsHmacSha196 = 18,
    Aes128CtsHmacSha256128 = 19,
    Aes256CtsHmacSha384192 = 20,
    Rc4Hmac = 23,
}

impl TryFrom<i32> for EncType {
    type Error = i32;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Null),
            1 => Ok(Self::DesCbcCrc),
            3 => Ok(Self::DesCbcMd5),
            16 => Ok(Self::Des3CbcSha1),
            17 => Ok(Self::Aes128CtsHmacSha196),
            18 => Ok(Self::Aes256CtsHmacSha196),
            19 => Ok(Self::Aes128CtsHmacSha256128),
            20 => Ok(Self::Aes256CtsHmacSha384192),
            23 => Ok(Self::Rc4Hmac),
            other => Err(other),
        }
    }
}

/// Checksum type identifiers (RFC 3961, RFC 4757).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum CksumType {
    RsaMd5 = 7,
    HmacSha196Aes128 = 15,
    HmacSha196Aes256 = 16,
    HmacSha256128Aes128 = 19,
    HmacSha384192Aes256 = 20,
    HmacMd5 = -138,
}

impl TryFrom<i32> for CksumType {
    type Error = i32;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            7 => Ok(Self::RsaMd5),
            15 => Ok(Self::HmacSha196Aes128),
            16 => Ok(Self::HmacSha196Aes256),
            19 => Ok(Self::HmacSha256128Aes128),
            20 => Ok(Self::HmacSha384192Aes256),
            -138 => Ok(Self::HmacMd5),
            other => Err(other),
        }
    }
}

/// Authorization data element types (RFC 4120 §7.5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum AuthDataType {
    IfRelevant = 1,
    KdcIssued = 4,
    AndOr = 5,
    MandatoryForKdc = 8,
    Win2kPac = 128,
    EtypeNegotiation = 129,
}

impl TryFrom<i32> for AuthDataType {
    type Error = i32;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::IfRelevant),
            4 => Ok(Self::KdcIssued),
            5 => Ok(Self::AndOr),
            8 => Ok(Self::MandatoryForKdc),
            128 => Ok(Self::Win2kPac),
            129 => Ok(Self::EtypeNegotiation),
            other => Err(other),
        }
    }
}

/// Last-request types (RFC 4120 §5.4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum LrType {
    None = 0,
    LastTgtRequest = 1,
    LastInitialRequest = 2,
    NewestTgt = 3,
    LastRenewal = 4,
    LastRequest = 5,
    PasswordExpires = 6,
    AccountExpires = 7,
}

impl TryFrom<i32> for LrType {
    type Error = i32;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::LastTgtRequest),
            2 => Ok(Self::LastInitialRequest),
            3 => Ok(Self::NewestTgt),
            4 => Ok(Self::LastRenewal),
            5 => Ok(Self::LastRequest),
            6 => Ok(Self::PasswordExpires),
            7 => Ok(Self::AccountExpires),
            other => Err(other),
        }
    }
}
