//! Pre-authentication handling for AS exchange.
//!
//! Implements PA-ENC-TIMESTAMP (padata-type 2) and PA-ETYPE-INFO2
//! extraction from KDC error responses.

use crate::crypto::{find_etype, key_usage};
use crate::types::{
    EncryptedData, EtypeInfo2Entry, KerberosTime, PaData, PaDataType, PaEncTsEnc, PaPacRequest,
};
use crate::Krb5Error;

/// A pluggable pre-authentication mechanism.
///
/// Implementations handle specific PA-DATA types (e.g., PA-ENC-TIMESTAMP,
/// PKINIT, encrypted challenge). This trait provides an extension point that
/// AS exchange implementations or callers can use to satisfy the KDC's
/// METHOD-DATA requirements; wiring of plugins is left to higher-level code.
///
/// # Implementing a Plugin
///
/// ```rust,ignore
/// struct MyPreauthPlugin;
///
/// impl PreauthPlugin for MyPreauthPlugin {
///     fn pa_type(&self) -> i32 { 42 }
///
///     fn can_handle(&self, method_data: &[PaData]) -> bool {
///         method_data.iter().any(|pa| pa.padata_type == 42)
///     }
///
///     fn generate(&self, ctx: &PreauthContext) -> Result<Vec<PaData>, Krb5Error> {
///         // Build PA-DATA for type 42
///         Ok(vec![/* ... */])
///     }
/// }
/// ```
pub trait PreauthPlugin: Send + Sync {
    /// The PA-DATA type number this plugin handles.
    fn pa_type(&self) -> i32;

    /// Whether this plugin can handle the given METHOD-DATA from the KDC.
    fn can_handle(&self, method_data: &[PaData]) -> bool;

    /// Generate PA-DATA for inclusion in the AS-REQ.
    fn generate(&self, ctx: &PreauthContext) -> Result<Vec<PaData>, Krb5Error>;
}

/// Context passed to preauth plugins for generating PA-DATA.
pub struct PreauthContext<'a> {
    /// User's password (UTF-8 bytes).
    pub password: &'a [u8],
    /// Salt for string-to-key.
    pub salt: &'a [u8],
    /// Optional string-to-key parameters.
    pub s2kparams: Option<&'a [u8]>,
    /// Selected encryption type.
    pub etype: i32,
    /// Current timestamp.
    pub now: KerberosTime,
    /// Current microseconds.
    pub now_usec: i32,
}

/// Information extracted from PA-ETYPE-INFO2 in a PREAUTH_REQUIRED error.
#[derive(Debug, Clone)]
pub(crate) struct PreauthHint {
    /// The encryption type to use.
    pub etype: i32,
    /// Salt for string-to-key (UTF-8 bytes).
    ///
    /// `None` means the KDC did not provide a salt — the caller must compute
    /// the default salt. `Some(vec![])` is a valid explicit empty salt.
    pub salt: Option<Vec<u8>>,
    /// Optional string-to-key parameters (e.g., PBKDF2 iteration count).
    pub s2kparams: Option<Vec<u8>>,
}

/// Extract pre-authentication hints from the e-data of a KDC_ERR_PREAUTH_REQUIRED error.
///
/// The e-data is DER-encoded METHOD-DATA (SEQUENCE OF PA-DATA). We look for
/// PA-ETYPE-INFO2 (type 19) and select the first entry with a supported etype.
pub(crate) fn extract_preauth_hint(
    e_data: &[u8],
    supported_etypes: &[i32],
) -> Result<PreauthHint, Krb5Error> {
    // Decode METHOD-DATA (SEQUENCE OF PA-DATA)
    let method_data: Vec<PaData> = rasn::der::decode(e_data)?;

    // Find PA-ETYPE-INFO2 (padata-type 19)
    let etype_info2_pa = method_data
        .iter()
        .find(|pa| pa.padata_type == PaDataType::EtypeInfo2 as i32);

    let etype_info2_pa = match etype_info2_pa {
        Some(pa) => pa,
        None => return Err(Krb5Error::NoCommonEtype),
    };

    // Decode ETYPE-INFO2 (SEQUENCE OF ETYPE-INFO2-ENTRY)
    let entries: Vec<EtypeInfo2Entry> = rasn::der::decode(etype_info2_pa.padata_value.as_ref())?;

    // Select etype using client preference order: iterate client's etypes
    // and pick the first one that the KDC also offers and we can handle.
    for &client_etype in supported_etypes {
        if let Some(entry) = entries.iter().find(|e| e.etype == client_etype) {
            if find_etype(client_etype).is_ok() {
                let salt = entry.salt.as_ref().map(|s| s.as_bytes().to_vec());
                let s2kparams = entry.s2kparams.as_ref().map(|p| p.as_ref().to_vec());
                return Ok(PreauthHint {
                    etype: entry.etype,
                    salt,
                    s2kparams,
                });
            }
        }
    }

    Err(Krb5Error::NoCommonEtype)
}

/// Build a PA-ENC-TIMESTAMP padata element.
///
/// Encrypts the current timestamp with a key derived from the password.
pub(crate) fn build_pa_enc_timestamp(
    password: &[u8],
    salt: &[u8],
    s2kparams: Option<&[u8]>,
    etype: i32,
    now: KerberosTime,
    now_usec: Option<i32>,
) -> Result<PaData, Krb5Error> {
    let profile = find_etype(etype).map_err(|_| Krb5Error::UnsupportedEtype(etype))?;

    // Derive key from password
    let key = profile
        .string_to_key(password, salt, s2kparams)
        .map_err(|e| Krb5Error::Crypto(e.to_string()))?;

    // Build PA-ENC-TS-ENC
    let ts_enc = PaEncTsEnc {
        patimestamp: now,
        pausec: now_usec,
    };
    let ts_enc_der = rasn::der::encode(&ts_enc).map_err(Krb5Error::Asn1Encode)?;

    // Encrypt with key usage 1 (PA_ENC_TIMESTAMP)
    let cipher = profile
        .encrypt(&key, key_usage::PA_ENC_TIMESTAMP, &ts_enc_der)
        .map_err(|e| Krb5Error::Crypto(e.to_string()))?;

    // Wrap in EncryptedData
    let enc_data = EncryptedData {
        etype,
        kvno: None,
        cipher: cipher.into(),
    };
    let enc_data_der = rasn::der::encode(&enc_data).map_err(Krb5Error::Asn1Encode)?;

    Ok(PaData {
        padata_type: PaDataType::EncTimestamp as i32,
        padata_value: enc_data_der.into(),
    })
}

/// Build a PA-PAC-REQUEST padata element.
pub(crate) fn build_pa_pac_request(include_pac: bool) -> Result<PaData, Krb5Error> {
    let pac_req = PaPacRequest { include_pac };
    let der = rasn::der::encode(&pac_req).map_err(Krb5Error::Asn1Encode)?;
    Ok(PaData {
        padata_type: PaDataType::PaPacRequest as i32,
        padata_value: der.into(),
    })
}

/// Compute default salt for string-to-key when not provided by KDC.
///
/// Default: `REALM` + principal components concatenated (no separator).
/// Example: realm "EXAMPLE.COM", principal "user" → "EXAMPLE.COMuser"
pub(crate) fn default_salt(realm: &str, principal_components: &[impl AsRef<[u8]>]) -> Vec<u8> {
    let mut salt = Vec::with_capacity(realm.len() + 32);
    salt.extend_from_slice(realm.as_bytes());
    for comp in principal_components {
        salt.extend_from_slice(comp.as_ref());
    }
    salt
}

#[cfg(test)]
mod tests {
    use super::*;
    use rasn::types::GeneralString;

    #[test]
    fn test_default_salt_simple() {
        let salt = default_salt("EXAMPLE.COM", &["user".as_bytes()]);
        assert_eq!(salt, b"EXAMPLE.COMuser");
    }

    #[test]
    fn test_default_salt_multi_component() {
        let salt = default_salt(
            "EXAMPLE.COM",
            &["host".as_bytes(), "server.example.com".as_bytes()],
        );
        assert_eq!(salt, b"EXAMPLE.COMhostserver.example.com");
    }

    #[test]
    fn test_build_pa_pac_request() {
        let pa = build_pa_pac_request(true).expect("encode PA-PAC-REQUEST");
        assert_eq!(pa.padata_type, PaDataType::PaPacRequest as i32);
        // Should round-trip
        let decoded: PaPacRequest =
            rasn::der::decode(pa.padata_value.as_ref()).expect("decode PA-PAC-REQUEST");
        assert!(decoded.include_pac);
    }

    #[test]
    fn test_extract_preauth_hint_selects_supported_etype() {
        // Build a METHOD-DATA with PA-ETYPE-INFO2 containing AES-256 and AES-128
        let entries = vec![
            EtypeInfo2Entry {
                etype: 18, // AES-256
                salt: Some(GeneralString::from_bytes(b"EXAMPLE.COMuser").expect("valid salt")),
                s2kparams: None,
            },
            EtypeInfo2Entry {
                etype: 17, // AES-128
                salt: Some(GeneralString::from_bytes(b"EXAMPLE.COMuser").expect("valid salt")),
                s2kparams: None,
            },
        ];
        let etype_info2_der = rasn::der::encode(&entries).expect("encode ETYPE-INFO2");

        let method_data = vec![PaData {
            padata_type: PaDataType::EtypeInfo2 as i32,
            padata_value: etype_info2_der.into(),
        }];
        let e_data = rasn::der::encode(&method_data).expect("encode METHOD-DATA");

        // Client supports AES-256 and AES-128
        let hint = extract_preauth_hint(&e_data, &[18, 17]).expect("extract hint");
        assert_eq!(hint.etype, 18); // Should pick first matching: AES-256
        assert_eq!(hint.salt.as_deref(), Some(b"EXAMPLE.COMuser".as_slice()));
        assert!(hint.s2kparams.is_none());
    }

    #[test]
    fn test_extract_preauth_hint_no_common_etype() {
        let entries = vec![EtypeInfo2Entry {
            etype: 23, // RC4-HMAC (not registered in our ETYPE_REGISTRY)
            salt: None,
            s2kparams: None,
        }];
        let etype_info2_der = rasn::der::encode(&entries).expect("encode ETYPE-INFO2");

        let method_data = vec![PaData {
            padata_type: PaDataType::EtypeInfo2 as i32,
            padata_value: etype_info2_der.into(),
        }];
        let e_data = rasn::der::encode(&method_data).expect("encode METHOD-DATA");

        // Client only supports AES
        let result = extract_preauth_hint(&e_data, &[18, 17]);
        assert!(matches!(result, Err(Krb5Error::NoCommonEtype)));
    }
}
