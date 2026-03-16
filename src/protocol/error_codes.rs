//! KDC error codes (RFC 4120 §7.5.9).

/// KDC error code constants.
///
/// Covers all error codes defined in RFC 4120 Section 7.5.9.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum ErrorCode {
    /// No error.
    None = 0,
    /// Client's entry in database has expired.
    NameExp = 1,
    /// Server's entry in database has expired.
    ServiceExp = 2,
    /// Requested protocol version number not supported.
    BadPvno = 3,
    /// Client's key encrypted in old master key.
    COldMastKvno = 4,
    /// Server's key encrypted in old master key.
    SOldMastKvno = 5,
    /// Client not found in Kerberos database.
    CPrincipalUnknown = 6,
    /// Server not found in Kerberos database.
    SPrincipalUnknown = 7,
    /// Multiple principal entries in database.
    PrincipalNotUnique = 8,
    /// The client or server has a null key.
    NullKey = 9,
    /// Ticket not eligible for postdating.
    CannotPostdate = 10,
    /// Requested starttime is later than end time.
    NeverValid = 11,
    /// KDC policy rejects request.
    Policy = 12,
    /// KDC cannot accommodate requested option.
    BadOption = 13,
    /// KDC has no support for encryption type.
    EtypeNosupp = 14,
    /// KDC has no support for checksum type.
    SumtypeNosupp = 15,
    /// KDC has no support for padata type.
    PadataTypeNosupp = 16,
    /// KDC has no support for transited type.
    TrtypeNosupp = 17,
    /// Clients credentials have been revoked.
    ClientRevoked = 18,
    /// Credentials for server have been revoked.
    ServiceRevoked = 19,
    /// TGT has been revoked.
    TgtRevoked = 20,
    /// Client not yet valid — try again later.
    ClientNotyet = 21,
    /// Server not yet valid — try again later.
    ServiceNotyet = 22,
    /// Password has expired — change password to reset.
    KeyExpired = 23,
    /// Pre-authentication information was invalid.
    PreauthFailed = 24,
    /// Additional pre-authentication required.
    PreauthRequired = 25,
    /// Inappropriate type of checksum in PDU.
    BadIntegrity = 31,
    /// Key version is not available.
    KeyTooOld = 33,
    /// Ticket is not yet valid.
    TktNotYetValid = 35,
    /// Request is a replay.
    Repeat = 36,
    /// Clock skew too great.
    Skew = 37,
    /// Incorrect net address.
    Badaddr = 38,
    /// Protocol version mismatch.
    Badversion = 39,
    /// Invalid msg type.
    MsgType = 40,
    /// Message stream modified.
    Modified = 41,
    /// Message out of order.
    BadOrder = 42,
    /// Specified version of key is not available.
    KeyVersionNotAvailable = 44,
    /// Service key not available.
    ServiceKeyNotAvailable = 45,
    /// Mutual authentication failed.
    MutualFailed = 46,
    /// Incorrect message direction.
    BadDirection = 47,
    /// Alternative authentication method required.
    MethodRequired = 48,
    /// Incorrect sequence number in message.
    BadSeq = 49,
    /// Inappropriate type of checksum in PDU.
    InappropriateType = 50,
    /// Response too big for UDP; retry with TCP.
    ResponseTooBig = 52,
    /// Generic error.
    Generic = 60,
    /// Field is too long for implementation.
    FieldToolong = 61,
    /// Client not trusted.
    ClientNotTrusted = 62,
    /// KDC not trusted.
    KdcNotTrusted = 63,
    /// Signature is invalid.
    InvalidSig = 64,
    /// Diffie-Hellman key parameters not accepted.
    DhKeyParamsNotAccepted = 65,
    /// Certificate not valid.
    CertificateRevoked = 66,
    /// Key/certificate not within etype.
    CertificateMismatch = 67,
    /// Wrong realm.
    WrongRealm = 68,
    /// No matching user found in certificate.
    UserToUserRequired = 69,
    /// Can't verify certificate.
    CantVerifyCertificate = 70,
    /// Invalid certificate.
    InvalidCertificate = 71,
    /// Revoked certificate.
    RevokedCertificate = 72,
    /// Revocation status unknown.
    RevocationStatusUnknown = 73,
    /// Revocation status unavailable.
    RevocationStatusUnavailable = 74,
    /// Client name mismatch in certificate.
    ClientNameMismatch = 75,
    /// KDC name mismatch in certificate.
    KdcNameMismatch = 76,
}

impl ErrorCode {
    /// Convert from an i32 error code. Returns `None` for unknown codes.
    pub fn from_i32(code: i32) -> Option<Self> {
        match code {
            0 => Some(Self::None),
            1 => Some(Self::NameExp),
            2 => Some(Self::ServiceExp),
            3 => Some(Self::BadPvno),
            4 => Some(Self::COldMastKvno),
            5 => Some(Self::SOldMastKvno),
            6 => Some(Self::CPrincipalUnknown),
            7 => Some(Self::SPrincipalUnknown),
            8 => Some(Self::PrincipalNotUnique),
            9 => Some(Self::NullKey),
            10 => Some(Self::CannotPostdate),
            11 => Some(Self::NeverValid),
            12 => Some(Self::Policy),
            13 => Some(Self::BadOption),
            14 => Some(Self::EtypeNosupp),
            15 => Some(Self::SumtypeNosupp),
            16 => Some(Self::PadataTypeNosupp),
            17 => Some(Self::TrtypeNosupp),
            18 => Some(Self::ClientRevoked),
            19 => Some(Self::ServiceRevoked),
            20 => Some(Self::TgtRevoked),
            21 => Some(Self::ClientNotyet),
            22 => Some(Self::ServiceNotyet),
            23 => Some(Self::KeyExpired),
            24 => Some(Self::PreauthFailed),
            25 => Some(Self::PreauthRequired),
            31 => Some(Self::BadIntegrity),
            33 => Some(Self::KeyTooOld),
            35 => Some(Self::TktNotYetValid),
            36 => Some(Self::Repeat),
            37 => Some(Self::Skew),
            38 => Some(Self::Badaddr),
            39 => Some(Self::Badversion),
            40 => Some(Self::MsgType),
            41 => Some(Self::Modified),
            42 => Some(Self::BadOrder),
            44 => Some(Self::KeyVersionNotAvailable),
            45 => Some(Self::ServiceKeyNotAvailable),
            46 => Some(Self::MutualFailed),
            47 => Some(Self::BadDirection),
            48 => Some(Self::MethodRequired),
            49 => Some(Self::BadSeq),
            50 => Some(Self::InappropriateType),
            52 => Some(Self::ResponseTooBig),
            60 => Some(Self::Generic),
            68 => Some(Self::WrongRealm),
            _ => None,
        }
    }

    /// Human-readable description of the error code.
    pub fn description(self) -> &'static str {
        match self {
            Self::None => "No error",
            Self::NameExp => "Client's entry in database has expired",
            Self::ServiceExp => "Server's entry in database has expired",
            Self::BadPvno => "Requested protocol version number not supported",
            Self::COldMastKvno => "Client's key encrypted in old master key",
            Self::SOldMastKvno => "Server's key encrypted in old master key",
            Self::CPrincipalUnknown => "Client not found in Kerberos database",
            Self::SPrincipalUnknown => "Server not found in Kerberos database",
            Self::PrincipalNotUnique => "Multiple principal entries in database",
            Self::NullKey => "The client or server has a null key",
            Self::CannotPostdate => "Ticket not eligible for postdating",
            Self::NeverValid => "Requested starttime is later than end time",
            Self::Policy => "KDC policy rejects request",
            Self::BadOption => "KDC cannot accommodate requested option",
            Self::EtypeNosupp => "KDC has no support for encryption type",
            Self::SumtypeNosupp => "KDC has no support for checksum type",
            Self::PadataTypeNosupp => "KDC has no support for padata type",
            Self::TrtypeNosupp => "KDC has no support for transited type",
            Self::ClientRevoked => "Clients credentials have been revoked",
            Self::ServiceRevoked => "Credentials for server have been revoked",
            Self::TgtRevoked => "TGT has been revoked",
            Self::ClientNotyet => "Client not yet valid",
            Self::ServiceNotyet => "Server not yet valid",
            Self::KeyExpired => "Password has expired",
            Self::PreauthFailed => "Pre-authentication information was invalid",
            Self::PreauthRequired => "Additional pre-authentication required",
            Self::BadIntegrity => "Inappropriate type of checksum in PDU",
            Self::KeyTooOld => "Key version is not available",
            Self::TktNotYetValid => "Ticket is not yet valid",
            Self::Repeat => "Request is a replay",
            Self::Skew => "Clock skew too great",
            Self::Badaddr => "Incorrect net address",
            Self::Badversion => "Protocol version mismatch",
            Self::MsgType => "Invalid msg type",
            Self::Modified => "Message stream modified",
            Self::BadOrder => "Message out of order",
            Self::KeyVersionNotAvailable => "Specified version of key is not available",
            Self::ServiceKeyNotAvailable => "Service key not available",
            Self::MutualFailed => "Mutual authentication failed",
            Self::BadDirection => "Incorrect message direction",
            Self::MethodRequired => "Alternative authentication method required",
            Self::BadSeq => "Incorrect sequence number in message",
            Self::InappropriateType => "Inappropriate type of checksum in PDU",
            Self::ResponseTooBig => "Response too big for UDP; retry with TCP",
            Self::Generic => "Generic error",
            Self::FieldToolong => "Field is too long for implementation",
            Self::ClientNotTrusted => "Client not trusted",
            Self::KdcNotTrusted => "KDC not trusted",
            Self::InvalidSig => "Signature is invalid",
            Self::DhKeyParamsNotAccepted => "DH key parameters not accepted",
            Self::CertificateRevoked => "Certificate not valid",
            Self::CertificateMismatch => "Key/certificate not within etype",
            Self::WrongRealm => "Wrong realm",
            Self::UserToUserRequired => "User to user required",
            Self::CantVerifyCertificate => "Can't verify certificate",
            Self::InvalidCertificate => "Invalid certificate",
            Self::RevokedCertificate => "Revoked certificate",
            Self::RevocationStatusUnknown => "Revocation status unknown",
            Self::RevocationStatusUnavailable => "Revocation status unavailable",
            Self::ClientNameMismatch => "Client name mismatch in certificate",
            Self::KdcNameMismatch => "KDC name mismatch in certificate",
        }
    }
}

impl core::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} ({})", self.description(), *self as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_i32_known_codes() {
        assert_eq!(ErrorCode::from_i32(6), Some(ErrorCode::CPrincipalUnknown));
        assert_eq!(ErrorCode::from_i32(25), Some(ErrorCode::PreauthRequired));
        assert_eq!(ErrorCode::from_i32(52), Some(ErrorCode::ResponseTooBig));
        assert_eq!(ErrorCode::from_i32(68), Some(ErrorCode::WrongRealm));
    }

    #[test]
    fn test_from_i32_unknown_code() {
        assert_eq!(ErrorCode::from_i32(999), None);
    }

    #[test]
    fn test_display() {
        let code = ErrorCode::PreauthRequired;
        let s = format!("{code}");
        assert!(s.contains("25"));
        assert!(s.contains("pre-authentication"));
    }
}
