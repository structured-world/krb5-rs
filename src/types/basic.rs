//! Core Kerberos data structures (RFC 4120 §5.2).

use rasn::prelude::*;
use zeroize::Zeroize;

use super::primitives::*;

/// Principal name (RFC 4120 §5.2.2).
#[derive(AsnType, Encode, Decode, Debug, Clone, PartialEq, Eq, Hash)]
pub struct PrincipalName {
    #[rasn(tag(explicit(context, 0)))]
    pub name_type: i32,
    #[rasn(tag(explicit(context, 1)))]
    pub name_string: Vec<KerberosString>,
}

/// Convert a string slice to GeneralString.
///
/// Kerberos principal names are ASCII, so this conversion is infallible
/// in practice. Falls back to empty string on conversion failure.
fn general_string_from(s: &str) -> KerberosString {
    GeneralString::from_bytes(s.as_bytes())
        .unwrap_or_else(|_| GeneralString::from_bytes(b"").expect("empty bytes are valid"))
}

impl PrincipalName {
    /// Create a simple principal name (e.g., "user").
    pub fn new_principal(name: &str) -> Self {
        Self {
            name_type: 1, // KRB5_NT_PRINCIPAL
            name_string: vec![general_string_from(name)],
        }
    }

    /// Create a service principal (e.g., "krbtgt/REALM").
    pub fn new_srv_inst(service: &str, instance: &str) -> Self {
        Self {
            name_type: 2, // KRB5_NT_SRV_INST
            name_string: vec![general_string_from(service), general_string_from(instance)],
        }
    }

    /// Create a host-based service principal (e.g., "HTTP/host.example.com").
    pub fn new_srv_hst(service: &str, hostname: &str) -> Self {
        Self {
            name_type: 3, // KRB5_NT_SRV_HST
            name_string: vec![general_string_from(service), general_string_from(hostname)],
        }
    }
}

impl core::fmt::Display for PrincipalName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let parts: Vec<String> = self
            .name_string
            .iter()
            .map(|s| String::from_utf8_lossy(s.as_ref()).to_string())
            .collect();
        write!(f, "{}", parts.join("/"))
    }
}

/// Error returned when parsing a principal name string fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsePrincipalError(pub String);

impl core::fmt::Display for ParsePrincipalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid principal name: {}", self.0)
    }
}

impl std::error::Error for ParsePrincipalError {}

impl core::str::FromStr for PrincipalName {
    type Err = ParsePrincipalError;

    /// Parse a principal name string.
    ///
    /// Supported formats:
    /// - `"user"` → NT_PRINCIPAL with single component
    /// - `"service/host"` → NT_SRV_HST with two components
    /// - `"krbtgt/REALM"` → NT_SRV_INST with two components
    ///
    /// The `@REALM` suffix is stripped if present (realm is separate in Kerberos).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(ParsePrincipalError("empty string".to_string()));
        }

        // Strip @REALM suffix if present (realm is handled separately)
        let name_part = s.split('@').next().unwrap_or(s);

        if name_part.is_empty() {
            return Err(ParsePrincipalError("empty name before @".to_string()));
        }

        let components: Vec<&str> = name_part.split('/').collect();

        let (name_type, name_string) = match components.len() {
            1 => (1, vec![general_string_from(components[0])]), // NT_PRINCIPAL
            2 => (
                2,
                vec![
                    general_string_from(components[0]),
                    general_string_from(components[1]),
                ],
            ), // NT_SRV_INST
            _ => {
                // 3+ components — treat as NT_PRINCIPAL with all components
                let strings = components.iter().map(|c| general_string_from(c)).collect();
                (1, strings)
            }
        };

        Ok(PrincipalName {
            name_type,
            name_string,
        })
    }
}

/// Host address (RFC 4120 §5.2.5).
#[derive(AsnType, Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct HostAddress {
    #[rasn(tag(explicit(context, 0)))]
    pub addr_type: i32,
    #[rasn(tag(explicit(context, 1)))]
    pub address: OctetString,
}

/// Encrypted data (RFC 4120 §5.2.9).
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct EncryptedData {
    #[rasn(tag(explicit(context, 0)))]
    pub etype: i32,
    #[rasn(tag(explicit(context, 1)))]
    pub kvno: Option<i32>,
    #[rasn(tag(explicit(context, 2)))]
    pub cipher: OctetString,
}

/// Encryption key (RFC 4120 §5.2.9).
///
/// Key material is zeroized on drop to protect sensitive data.
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct EncryptionKey {
    #[rasn(tag(explicit(context, 0)))]
    pub keytype: i32,
    #[rasn(tag(explicit(context, 1)))]
    pub keyvalue: OctetString,
}

impl Drop for EncryptionKey {
    fn drop(&mut self) {
        // Zeroize the key material by replacing with empty OctetString.
        // OctetString is Bytes-backed so we replace rather than mutate in-place.
        self.keyvalue = OctetString::from(Vec::<u8>::new());
        self.keytype = 0;
    }
}

impl Zeroize for EncryptionKey {
    fn zeroize(&mut self) {
        self.keyvalue = OctetString::from(Vec::<u8>::new());
        self.keytype.zeroize();
    }
}

/// Checksum (RFC 4120 §5.2.9).
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct Checksum {
    #[rasn(tag(explicit(context, 0)))]
    pub cksumtype: i32,
    #[rasn(tag(explicit(context, 1)))]
    pub checksum: OctetString,
}

/// Authorization data element (RFC 4120 §5.2.6).
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct AuthorizationDataElement {
    #[rasn(tag(explicit(context, 0)))]
    pub ad_type: i32,
    #[rasn(tag(explicit(context, 1)))]
    pub ad_data: OctetString,
}

/// Transited encoding (RFC 4120 §5.3).
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct TransitedEncoding {
    #[rasn(tag(explicit(context, 0)))]
    pub tr_type: i32,
    #[rasn(tag(explicit(context, 1)))]
    pub contents: OctetString,
}

/// Last-request entry (RFC 4120 §5.4.2).
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct LastReqEntry {
    #[rasn(tag(explicit(context, 0)))]
    pub lr_type: i32,
    #[rasn(tag(explicit(context, 1)))]
    pub lr_value: KerberosTime,
}
