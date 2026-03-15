//! Core Kerberos data structures (RFC 4120 §5.2).

use rasn::prelude::*;
use rasn::types::Identifier;
use zeroize::{Zeroize, Zeroizing};

use super::primitives::*;

/// Principal name (RFC 4120 §5.2.2).
#[derive(AsnType, Encode, Decode, Debug, Clone, PartialEq, Eq, Hash)]
pub struct PrincipalName {
    #[rasn(tag(explicit(context, 0)))]
    pub name_type: i32,
    #[rasn(tag(explicit(context, 1)))]
    pub name_string: Vec<KerberosString>,
}

/// Convert a string slice to GeneralString, returning error on invalid bytes.
fn try_general_string(s: &str) -> Result<KerberosString, ParsePrincipalError> {
    GeneralString::from_bytes(s.as_bytes())
        .map_err(|e| ParsePrincipalError(format!("invalid principal component {s:?}: {e}")))
}

impl PrincipalName {
    /// Create a simple principal name (e.g., "user").
    ///
    /// # Panics
    /// Panics if `name` contains non-printable characters.
    pub fn new_principal(name: &str) -> Self {
        Self {
            name_type: 1, // KRB5_NT_PRINCIPAL
            name_string: vec![try_general_string(name).expect("valid principal name")],
        }
    }

    /// Create a service principal (e.g., "krbtgt/REALM").
    ///
    /// # Panics
    /// Panics if arguments contain non-printable characters.
    pub fn new_srv_inst(service: &str, instance: &str) -> Self {
        Self {
            name_type: 2, // KRB5_NT_SRV_INST
            name_string: vec![
                try_general_string(service).expect("valid service name"),
                try_general_string(instance).expect("valid instance name"),
            ],
        }
    }

    /// Create a host-based service principal (e.g., "HTTP/host.example.com").
    ///
    /// # Panics
    /// Panics if arguments contain non-printable characters.
    pub fn new_srv_hst(service: &str, hostname: &str) -> Self {
        Self {
            name_type: 3, // KRB5_NT_SRV_HST
            name_string: vec![
                try_general_string(service).expect("valid service name"),
                try_general_string(hostname).expect("valid hostname"),
            ],
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
    /// - `"user"` → NT_PRINCIPAL (1) with single component
    /// - `"service/host"` → NT_SRV_HST (3) with two components
    ///
    /// Two-component principals default to NT_SRV_HST because the common
    /// case for parsed strings is SPN format ("HTTP/host"). Use
    /// `new_srv_inst()` directly for krbtgt-style principals.
    ///
    /// The `@REALM` suffix is stripped if present (realm is separate in Kerberos).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(ParsePrincipalError("empty string".to_string()));
        }

        // Reject multiple @ separators (e.g., "user@REALM@EXTRA")
        if s.matches('@').count() > 1 {
            return Err(ParsePrincipalError("multiple '@' separators".to_string()));
        }

        // Strip @REALM suffix if present (realm is handled separately)
        let name_part = s.split('@').next().unwrap_or(s);

        if name_part.is_empty() {
            return Err(ParsePrincipalError("empty name before @".to_string()));
        }

        let components: Vec<&str> = name_part.split('/').collect();

        // Reject empty components (e.g., "service/", "/host", "a//b")
        for comp in &components {
            if comp.is_empty() {
                return Err(ParsePrincipalError(
                    "empty component in principal name".to_string(),
                ));
            }
        }

        // Two-component principals use NT_SRV_HST (3), consistent with
        // new_srv_hst(). For krbtgt-style (NT_SRV_INST=2), use new_srv_inst().
        let (name_type, name_string) = match components.len() {
            1 => (1, vec![try_general_string(components[0])?]), // NT_PRINCIPAL
            2 => (
                3,
                vec![
                    try_general_string(components[0])?,
                    try_general_string(components[1])?,
                ],
            ), // NT_SRV_HST
            _ => {
                // 3+ components — treat as NT_PRINCIPAL with all components
                let strings: Result<Vec<_>, _> =
                    components.iter().map(|c| try_general_string(c)).collect();
                (1, strings?)
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
/// Key material is stored in `Zeroizing<Vec<u8>>` — guaranteed zeroed on drop.
/// Converted to/from OctetString only during ASN.1 encode/decode via custom impls.
///
/// `Debug` is redacted to prevent key leakage in logs/panics.
#[derive(Clone)]
pub struct EncryptionKey {
    /// Encryption type identifier.
    pub keytype: i32,
    /// Key material — zeroized on drop. Access via `key_bytes()`.
    key_bytes: Zeroizing<Vec<u8>>,
}

impl EncryptionKey {
    /// Create a new encryption key with secure storage.
    pub fn new(keytype: i32, key_bytes: Vec<u8>) -> Self {
        Self {
            keytype,
            key_bytes: Zeroizing::new(key_bytes),
        }
    }

    /// Access the raw key bytes.
    pub fn key_bytes(&self) -> &[u8] {
        &self.key_bytes
    }
}

impl core::fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EncryptionKey")
            .field("keytype", &self.keytype)
            .field(
                "keyvalue",
                &format_args!("<{} bytes redacted>", self.key_bytes.len()),
            )
            .finish()
    }
}

impl Zeroize for EncryptionKey {
    fn zeroize(&mut self) {
        self.key_bytes.zeroize();
        self.keytype = 0;
    }
}

// --- Custom ASN.1 Encode/Decode ---
// Store key in Zeroizing<Vec<u8>> in memory, serialize as OctetString on wire.

/// Wire format helper (rasn derive handles the ASN.1 tags).
#[derive(AsnType, Encode, Decode)]
struct EncryptionKeyWire {
    #[rasn(tag(explicit(context, 0)))]
    keytype: i32,
    #[rasn(tag(explicit(context, 1)))]
    keyvalue: OctetString,
}

impl rasn::AsnType for EncryptionKey {
    const TAG: Tag = Tag::SEQUENCE;
    const TAG_TREE: TagTree = TagTree::Leaf(Tag::SEQUENCE);
}

impl rasn::Encode for EncryptionKey {
    fn encode_with_tag_and_constraints<'b, E: rasn::Encoder<'b>>(
        &self,
        encoder: &mut E,
        tag: Tag,
        constraints: Constraints,
        identifier: Identifier,
    ) -> Result<(), E::Error> {
        let wire = EncryptionKeyWire {
            keytype: self.keytype,
            keyvalue: OctetString::from((*self.key_bytes).clone()),
        };
        wire.encode_with_tag_and_constraints(encoder, tag, constraints, identifier)
    }
}

impl rasn::Decode for EncryptionKey {
    fn decode_with_tag_and_constraints<D: rasn::Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        let wire = EncryptionKeyWire::decode_with_tag_and_constraints(decoder, tag, constraints)?;
        Ok(EncryptionKey::new(wire.keytype, wire.keyvalue.to_vec()))
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
