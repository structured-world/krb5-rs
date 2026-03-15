//! Round-trip DER encode/decode tests for all Kerberos ASN.1 types.
//!
//! Each test constructs a value, encodes it to DER, decodes it back,
//! re-encodes, and verifies the bytes match (canonical DER property).

use rasn::prelude::*;
use rasn::{ber, der};

use chrono::{TimeZone, Utc};
use krb5_rs::types::*;
use zeroize::Zeroize;

/// Helper: encode to DER, decode back, re-encode, assert bytes match.
fn roundtrip<T: rasn::Encode + rasn::Decode + core::fmt::Debug>(value: &T) {
    let encoded = der::encode(value).expect("DER encode failed");
    let decoded: T = der::decode(&encoded).expect("DER decode failed");
    let re_encoded = der::encode(&decoded).expect("DER re-encode failed");
    assert_eq!(encoded, re_encoded, "Round-trip mismatch for {:?}", decoded);
}

/// Helper: roundtrip with semantic equality check for types implementing PartialEq.
fn roundtrip_eq<T: rasn::Encode + rasn::Decode + core::fmt::Debug + PartialEq>(value: &T) {
    let encoded = der::encode(value).expect("DER encode failed");
    let decoded: T = der::decode(&encoded).expect("DER decode failed");
    assert_eq!(&decoded, value, "Semantic mismatch after decode");
    let re_encoded = der::encode(&decoded).expect("DER re-encode failed");
    assert_eq!(encoded, re_encoded, "Round-trip mismatch for {:?}", decoded);
}

fn make_realm() -> Realm {
    GeneralString::from_bytes(b"EXAMPLE.COM").expect("valid realm")
}

fn make_principal() -> PrincipalName {
    PrincipalName::new_principal("testuser")
}

fn make_srv_principal() -> PrincipalName {
    PrincipalName::new_srv_inst("krbtgt", "EXAMPLE.COM")
}

fn make_encrypted_data() -> EncryptedData {
    EncryptedData {
        etype: 18, // AES256
        kvno: Some(2),
        cipher: OctetString::from(vec![0x01, 0x02, 0x03, 0x04]),
    }
}

fn make_encryption_key() -> EncryptionKey {
    EncryptionKey::new(18, vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
}

fn make_checksum() -> Checksum {
    Checksum {
        cksumtype: 16,
        checksum: OctetString::from(vec![0x11, 0x22, 0x33]),
    }
}

fn make_time() -> KerberosTime {
    Utc.with_ymd_and_hms(2026, 3, 15, 12, 0, 0)
        .unwrap()
        .fixed_offset()
}

fn make_bitstring_flags() -> BitString {
    BitString::from_slice(&[0x40, 0x80, 0x00, 0x00])
}

// --- Primitive/Basic type tests ---

#[test]
fn test_principal_name_roundtrip() {
    roundtrip_eq(&make_principal());
}

#[test]
fn test_principal_name_srv_inst_roundtrip() {
    roundtrip(&make_srv_principal());
}

#[test]
fn test_principal_name_srv_hst_roundtrip() {
    let p = PrincipalName::new_srv_hst("HTTP", "web.example.com");
    roundtrip_eq(&p);
    assert_eq!(p.to_string(), "HTTP/web.example.com");
}

#[test]
fn test_principal_name_display() {
    let p = PrincipalName::new_principal("user");
    assert_eq!(p.to_string(), "user");

    let s = PrincipalName::new_srv_inst("krbtgt", "EXAMPLE.COM");
    assert_eq!(s.to_string(), "krbtgt/EXAMPLE.COM");
}

#[test]
fn test_host_address_roundtrip() {
    let addr = HostAddress {
        addr_type: 2, // IPv4
        address: OctetString::from(vec![192, 168, 1, 1]),
    };
    roundtrip_eq(&addr);
}

#[test]
fn test_encrypted_data_roundtrip() {
    roundtrip(&make_encrypted_data());
}

#[test]
fn test_encrypted_data_no_kvno() {
    let ed = EncryptedData {
        etype: 17,
        kvno: None,
        cipher: OctetString::from(vec![0xaa]),
    };
    roundtrip(&ed);
}

#[test]
fn test_encryption_key_roundtrip() {
    roundtrip(&make_encryption_key());
}

#[test]
fn test_checksum_roundtrip() {
    roundtrip(&make_checksum());
}

#[test]
fn test_authorization_data_element_roundtrip() {
    let ade = AuthorizationDataElement {
        ad_type: 1,
        ad_data: OctetString::from(vec![0x00, 0x01]),
    };
    roundtrip(&ade);
}

#[test]
fn test_transited_encoding_roundtrip() {
    let te = TransitedEncoding {
        tr_type: 1,
        contents: OctetString::from(b"REALM-A,REALM-B".to_vec()),
    };
    roundtrip(&te);
}

#[test]
fn test_last_req_entry_roundtrip() {
    let lre = LastReqEntry {
        lr_type: 6,
        lr_value: make_time(),
    };
    roundtrip(&lre);
}

// --- Ticket tests ---

#[test]
fn test_ticket_roundtrip() {
    let ticket = Ticket {
        tkt_vno: 5,
        realm: make_realm(),
        sname: make_srv_principal(),
        enc_part: make_encrypted_data(),
    };
    roundtrip(&ticket);
}

#[test]
fn test_ticket_application_tag() {
    // Ticket has APPLICATION 1 tag. Verify encoding starts with 0x61 (constructed APPLICATION 1).
    let ticket = Ticket {
        tkt_vno: 5,
        realm: make_realm(),
        sname: make_srv_principal(),
        enc_part: make_encrypted_data(),
    };
    let encoded = der::encode(&ticket).unwrap();
    assert_eq!(
        encoded[0], 0x61,
        "Ticket should have APPLICATION 1 tag (0x61)"
    );
}

// --- Pre-auth tests ---

#[test]
fn test_pa_data_roundtrip() {
    let pad = PaData {
        padata_type: 2,
        padata_value: OctetString::from(vec![0x30, 0x05]),
    };
    roundtrip(&pad);
}

#[test]
fn test_pa_enc_ts_enc_roundtrip() {
    let ts = PaEncTsEnc {
        patimestamp: make_time(),
        pausec: Some(123456),
    };
    roundtrip(&ts);
}

#[test]
fn test_pa_enc_ts_enc_no_usec() {
    let ts = PaEncTsEnc {
        patimestamp: make_time(),
        pausec: None,
    };
    roundtrip(&ts);
}

#[test]
fn test_pa_pac_request_roundtrip() {
    let pac = PaPacRequest { include_pac: true };
    roundtrip(&pac);
    let pac_false = PaPacRequest { include_pac: false };
    roundtrip(&pac_false);
}

#[test]
fn test_etype_info2_entry_roundtrip() {
    let entry = EtypeInfo2Entry {
        etype: 18,
        salt: Some(GeneralString::from_bytes(b"EXAMPLE.COMtestuser").expect("valid salt")),
        s2kparams: None,
    };
    roundtrip(&entry);
}

// --- KDC exchange tests ---

#[test]
fn test_kdc_req_body_roundtrip() {
    let body = KdcReqBody {
        kdc_options: make_bitstring_flags(),
        cname: Some(make_principal()),
        realm: make_realm(),
        sname: Some(make_srv_principal()),
        from: None,
        till: make_time(),
        rtime: None,
        nonce: 12345678,
        etype: vec![18, 17],
        addresses: None,
        enc_authorization_data: None,
        additional_tickets: None,
    };
    roundtrip(&body);
}

#[test]
fn test_as_req_roundtrip() {
    let req = AsReq(KdcReq {
        pvno: 5,
        msg_type: 10,
        padata: None,
        req_body: KdcReqBody {
            kdc_options: make_bitstring_flags(),
            cname: Some(make_principal()),
            realm: make_realm(),
            sname: Some(make_srv_principal()),
            from: None,
            till: make_time(),
            rtime: None,
            nonce: 42,
            etype: vec![18, 17],
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        },
    });
    roundtrip(&req);
}

#[test]
fn test_as_req_application_tag() {
    let req = AsReq(KdcReq {
        pvno: 5,
        msg_type: 10,
        padata: None,
        req_body: KdcReqBody {
            kdc_options: make_bitstring_flags(),
            cname: Some(make_principal()),
            realm: make_realm(),
            sname: Some(make_srv_principal()),
            from: None,
            till: make_time(),
            rtime: None,
            nonce: 42,
            etype: vec![18],
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        },
    });
    let encoded = der::encode(&req).unwrap();
    // APPLICATION 10 = 0x6a (constructed)
    assert_eq!(
        encoded[0], 0x6a,
        "AS-REQ should have APPLICATION 10 tag (0x6a)"
    );
}

#[test]
fn test_tgs_req_application_tag() {
    let req = TgsReq(KdcReq {
        pvno: 5,
        msg_type: 12,
        padata: None,
        req_body: KdcReqBody {
            kdc_options: make_bitstring_flags(),
            cname: None,
            realm: make_realm(),
            sname: Some(PrincipalName::new_srv_hst("HTTP", "web.example.com")),
            from: None,
            till: make_time(),
            rtime: None,
            nonce: 99,
            etype: vec![18],
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        },
    });
    let encoded = der::encode(&req).unwrap();
    // APPLICATION 12 = 0x6c (constructed)
    assert_eq!(
        encoded[0], 0x6c,
        "TGS-REQ should have APPLICATION 12 tag (0x6c)"
    );
}

#[test]
fn test_as_rep_roundtrip() {
    let rep = AsRep(KdcRep {
        pvno: 5,
        msg_type: 11,
        padata: None,
        crealm: make_realm(),
        cname: make_principal(),
        ticket: Ticket {
            tkt_vno: 5,
            realm: make_realm(),
            sname: make_srv_principal(),
            enc_part: make_encrypted_data(),
        },
        enc_part: make_encrypted_data(),
    });
    roundtrip(&rep);
}

#[test]
fn test_enc_kdc_rep_part_roundtrip() {
    let part = EncKdcRepPart {
        key: make_encryption_key(),
        last_req: vec![LastReqEntry {
            lr_type: 0,
            lr_value: make_time(),
        }],
        nonce: 42,
        key_expiration: None,
        flags: make_bitstring_flags(),
        authtime: make_time(),
        starttime: None,
        endtime: make_time(),
        renew_till: None,
        srealm: make_realm(),
        sname: make_srv_principal(),
        caddr: None,
        encrypted_pa_data: None,
    };
    roundtrip(&part);
}

// --- AP exchange tests ---

#[test]
fn test_ap_req_roundtrip() {
    let req = ApReq {
        pvno: 5,
        msg_type: 14,
        ap_options: make_bitstring_flags(),
        ticket: Ticket {
            tkt_vno: 5,
            realm: make_realm(),
            sname: make_srv_principal(),
            enc_part: make_encrypted_data(),
        },
        authenticator: make_encrypted_data(),
    };
    roundtrip(&req);
}

#[test]
fn test_ap_req_application_tag() {
    let req = ApReq {
        pvno: 5,
        msg_type: 14,
        ap_options: make_bitstring_flags(),
        ticket: Ticket {
            tkt_vno: 5,
            realm: make_realm(),
            sname: make_srv_principal(),
            enc_part: make_encrypted_data(),
        },
        authenticator: make_encrypted_data(),
    };
    let encoded = der::encode(&req).unwrap();
    // APPLICATION 14 = 0x6e (constructed)
    assert_eq!(
        encoded[0], 0x6e,
        "AP-REQ should have APPLICATION 14 tag (0x6e)"
    );
}

#[test]
fn test_authenticator_roundtrip() {
    let auth = Authenticator {
        authenticator_vno: 5,
        crealm: make_realm(),
        cname: make_principal(),
        cksum: Some(make_checksum()),
        cusec: 123,
        ctime: make_time(),
        subkey: Some(make_encryption_key()),
        seq_number: Some(1),
        authorization_data: None,
    };
    roundtrip(&auth);
}

#[test]
fn test_authenticator_minimal() {
    let auth = Authenticator {
        authenticator_vno: 5,
        crealm: make_realm(),
        cname: make_principal(),
        cksum: None,
        cusec: 0,
        ctime: make_time(),
        subkey: None,
        seq_number: None,
        authorization_data: None,
    };
    roundtrip(&auth);
}

#[test]
fn test_enc_ap_rep_part_roundtrip() {
    let part = EncApRepPart {
        ctime: make_time(),
        cusec: 456,
        subkey: Some(make_encryption_key()),
        seq_number: Some(2),
    };
    roundtrip(&part);
}

// --- KRB-ERROR test ---

#[test]
fn test_krb_error_msg_roundtrip() {
    let err = KrbErrorMsg {
        pvno: 5,
        msg_type: 30,
        ctime: None,
        cusec: None,
        stime: make_time(),
        susec: 0,
        error_code: 25, // PREAUTH_REQUIRED
        crealm: None,
        cname: None,
        realm: make_realm(),
        sname: make_srv_principal(),
        e_text: Some(GeneralString::from_bytes(b"Need preauth").expect("valid text")),
        e_data: Some(OctetString::from(vec![0x30, 0x00])),
    };
    roundtrip(&err);
}

#[test]
fn test_krb_error_application_tag() {
    let err = KrbErrorMsg {
        pvno: 5,
        msg_type: 30,
        ctime: None,
        cusec: None,
        stime: make_time(),
        susec: 0,
        error_code: 6,
        crealm: None,
        cname: None,
        realm: make_realm(),
        sname: make_srv_principal(),
        e_text: None,
        e_data: None,
    };
    let encoded = der::encode(&err).unwrap();
    // APPLICATION 30 = 0x7e (constructed)
    assert_eq!(
        encoded[0], 0x7e,
        "KRB-ERROR should have APPLICATION 30 tag (0x7e)"
    );
}

// --- Safe/Priv/Cred tests ---

#[test]
fn test_krb_safe_roundtrip() {
    let safe = KrbSafe {
        pvno: 5,
        msg_type: 20,
        safe_body: KrbSafeBody {
            user_data: OctetString::from(b"hello".to_vec()),
            timestamp: Some(make_time()),
            usec: Some(100),
            seq_number: Some(1),
            s_address: HostAddress {
                addr_type: 2,
                address: OctetString::from(vec![10, 0, 0, 1]),
            },
            r_address: None,
        },
        cksum: make_checksum(),
    };
    roundtrip(&safe);
}

#[test]
fn test_krb_cred_roundtrip() {
    let cred = KrbCred {
        pvno: 5,
        msg_type: 22,
        tickets: vec![Ticket {
            tkt_vno: 5,
            realm: make_realm(),
            sname: make_srv_principal(),
            enc_part: make_encrypted_data(),
        }],
        enc_part: make_encrypted_data(),
    };
    roundtrip(&cred);
}

// --- FAST type tests ---

#[test]
fn test_krb_fast_armor_roundtrip() {
    let armor = KrbFastArmor {
        armor_type: 1,
        armor_value: OctetString::from(vec![0xde, 0xad, 0xbe, 0xef]),
    };
    roundtrip(&armor);
}

#[test]
fn test_pa_fx_fast_request_roundtrip() {
    let req = PaFxFastRequest::ArmoredData(KrbFastArmoredReq {
        armor: Some(KrbFastArmor {
            armor_type: 1,
            armor_value: OctetString::from(vec![0x01]),
        }),
        req_checksum: make_checksum(),
        enc_fast_req: make_encrypted_data(),
    });
    roundtrip(&req);
}

#[test]
fn test_kdc_proxy_message_roundtrip() {
    let msg = KdcProxyMessage {
        kerb_message: OctetString::from(vec![0x6a, 0x10, 0x00]),
        target_domain: Some(make_realm()),
        dclocator_hint: None,
    };
    roundtrip(&msg);
}

// --- Flags tests ---

#[test]
fn test_kdc_options_flags() {
    let opts = KdcOptions::FORWARDABLE | KdcOptions::RENEWABLE | KdcOptions::CANONICALIZE;
    let bytes = opts.to_bytes();
    let restored = KdcOptions::from_bytes(&bytes);
    assert_eq!(opts, restored);
    assert!(restored.contains(KdcOptions::FORWARDABLE));
    assert!(restored.contains(KdcOptions::RENEWABLE));
    assert!(restored.contains(KdcOptions::CANONICALIZE));
    assert!(!restored.contains(KdcOptions::PROXIABLE));
}

#[test]
fn test_ticket_flags() {
    let flags = TicketFlags::FORWARDABLE | TicketFlags::INITIAL | TicketFlags::PRE_AUTHENT;
    let bytes = flags.to_bytes();
    let restored = TicketFlags::from_bytes(&bytes);
    assert_eq!(flags, restored);
}

#[test]
fn test_ap_options_flags() {
    let opts = ApOptions::MUTUAL_REQUIRED;
    let bytes = opts.to_bytes();
    let restored = ApOptions::from_bytes(&bytes);
    assert_eq!(opts, restored);
    assert!(restored.contains(ApOptions::MUTUAL_REQUIRED));
    assert!(!restored.contains(ApOptions::USE_SESSION_KEY));
}

// --- Enum conversion tests ---

#[test]
fn test_name_type_conversion() {
    assert_eq!(NameType::try_from(1), Ok(NameType::Principal));
    assert_eq!(NameType::try_from(10), Ok(NameType::Enterprise));
    assert_eq!(NameType::try_from(999), Err(999));
}

#[test]
fn test_enc_type_conversion() {
    assert_eq!(EncType::try_from(18), Ok(EncType::Aes256CtsHmacSha196));
    assert_eq!(EncType::try_from(23), Ok(EncType::Rc4Hmac));
    assert_eq!(EncType::try_from(-1), Err(-1));
}

#[test]
fn test_cksum_type_conversion() {
    assert_eq!(CksumType::try_from(-138), Ok(CksumType::HmacMd5));
    assert_eq!(CksumType::try_from(16), Ok(CksumType::HmacSha196Aes256));
}

// --- Cross-decode test: verify BER decoder can read DER output ---

#[test]
fn test_ber_can_decode_der_ticket() {
    let ticket = Ticket {
        tkt_vno: 5,
        realm: make_realm(),
        sname: make_srv_principal(),
        enc_part: make_encrypted_data(),
    };
    let der_bytes = der::encode(&ticket).unwrap();
    let ber_decoded: Ticket = ber::decode(&der_bytes).unwrap();
    let re_encoded = der::encode(&ber_decoded).unwrap();
    assert_eq!(der_bytes, re_encoded);
}

// --- EncryptionKey zeroize test ---

#[test]
fn test_encryption_key_zeroize() {
    let mut key = make_encryption_key();
    assert_eq!(key.key_bytes().len(), 6);
    assert_ne!(
        key.key_bytes(),
        &[0u8; 6],
        "key should not be zero before zeroize"
    );
    key.zeroize();
    assert_eq!(key.keytype, 0, "keytype must be zeroed");
    // Vec::zeroize() zeroes bytes in-place then clears the vec (len=0).
    // This is correct — key material was wiped before truncation,
    // and clearing length prevents leaking even the key size.
    assert!(
        key.key_bytes().is_empty(),
        "key_bytes must be empty after zeroize (zeroed then cleared)"
    );
}

#[test]
fn test_encryption_key_debug_redacted() {
    let key = make_encryption_key();
    let debug_output = format!("{:?}", key);
    assert!(
        debug_output.contains("redacted"),
        "Debug output must redact key bytes, got: {debug_output}"
    );
    assert!(
        !debug_output.contains("\\xaa"),
        "Debug output must not contain raw key bytes"
    );
}

// --- FromStr tests for PrincipalName ---

#[test]
fn test_principal_from_str_simple() {
    let p: PrincipalName = "testuser".parse().expect("parse simple principal");
    assert_eq!(p.name_type, 1); // NT_PRINCIPAL
    assert_eq!(p.name_string.len(), 1);
    assert_eq!(p.to_string(), "testuser");
}

#[test]
fn test_principal_from_str_service() {
    let p: PrincipalName = "krbtgt/EXAMPLE.COM"
        .parse()
        .expect("parse service principal");
    // FromStr uses NT_SRV_HST (3) for two-component principals.
    // Use new_srv_inst() directly for NT_SRV_INST (2) krbtgt-style.
    assert_eq!(p.name_type, 3); // NT_SRV_HST
    assert_eq!(p.name_string.len(), 2);
    assert_eq!(p.to_string(), "krbtgt/EXAMPLE.COM");
}

#[test]
fn test_principal_from_str_with_realm() {
    let p: PrincipalName = "user@EXAMPLE.COM"
        .parse()
        .expect("parse principal with realm");
    assert_eq!(p.name_type, 1); // NT_PRINCIPAL
    assert_eq!(p.name_string.len(), 1);
    assert_eq!(p.to_string(), "user"); // realm stripped
}

#[test]
fn test_principal_from_str_service_with_realm() {
    let p: PrincipalName = "HTTP/web.example.com@EXAMPLE.COM"
        .parse()
        .expect("parse SPN with realm");
    assert_eq!(p.name_type, 3); // NT_SRV_HST — consistent with new_srv_hst()
    assert_eq!(p.name_string.len(), 2);
    assert_eq!(p.to_string(), "HTTP/web.example.com");
}

#[test]
fn test_principal_from_str_empty() {
    let result = "".parse::<PrincipalName>();
    assert!(result.is_err());
}

#[test]
fn test_principal_from_str_at_only() {
    let result = "@REALM".parse::<PrincipalName>();
    assert!(result.is_err());
}

#[test]
fn test_principal_from_str_multiple_at() {
    let result = "user@REALM@EXTRA".parse::<PrincipalName>();
    assert!(result.is_err());
}

#[test]
fn test_principal_from_str_trailing_slash() {
    let result = "service/".parse::<PrincipalName>();
    assert!(result.is_err());
}

#[test]
fn test_principal_from_str_leading_slash() {
    let result = "/host".parse::<PrincipalName>();
    assert!(result.is_err());
}

#[test]
fn test_principal_from_str_double_slash() {
    let result = "a//b".parse::<PrincipalName>();
    assert!(result.is_err());
}

#[test]
fn test_principal_from_str_roundtrip() {
    // Parse and re-display should be consistent
    let original = "HTTP/host.example.com";
    let p: PrincipalName = original.parse().expect("parse");
    assert_eq!(p.to_string(), original);
    roundtrip_eq(&p);
}

// --- Type alias tests ---

#[test]
fn test_method_data_roundtrip() {
    let md: MethodData = vec![
        PaData {
            padata_type: 19,
            padata_value: OctetString::from(vec![0x30, 0x00]),
        },
        PaData {
            padata_type: 2,
            padata_value: OctetString::from(vec![0x30, 0x03]),
        },
    ];
    // MethodData is Vec<PaData> — encode as SEQUENCE OF
    let encoded = der::encode(&md).expect("encode MethodData");
    let decoded: MethodData = der::decode(&encoded).expect("decode MethodData");
    assert_eq!(decoded.len(), 2);
    assert_eq!(decoded[0].padata_type, 19);
    assert_eq!(decoded[1].padata_type, 2);
}

#[test]
fn test_etype_info2_roundtrip() {
    let info: EtypeInfo2 = vec![
        EtypeInfo2Entry {
            etype: 18,
            salt: Some(GeneralString::from_bytes(b"EXAMPLE.COMuser").expect("valid")),
            s2kparams: None,
        },
        EtypeInfo2Entry {
            etype: 17,
            salt: None,
            s2kparams: None,
        },
    ];
    let encoded = der::encode(&info).expect("encode EtypeInfo2");
    let decoded: EtypeInfo2 = der::decode(&encoded).expect("decode EtypeInfo2");
    assert_eq!(decoded.len(), 2);
    assert_eq!(decoded[0].etype, 18);
    assert_eq!(decoded[1].etype, 17);
}

// --- EncTicketPart roundtrip (complex type with many optional fields) ---

#[test]
fn test_enc_ticket_part_roundtrip() {
    let etp = EncTicketPart {
        flags: make_bitstring_flags(),
        key: make_encryption_key(),
        crealm: make_realm(),
        cname: make_principal(),
        transited: TransitedEncoding {
            tr_type: 1,
            contents: OctetString::from(b"".to_vec()),
        },
        authtime: make_time(),
        starttime: Some(make_time()),
        endtime: make_time(),
        renew_till: Some(make_time()),
        caddr: None,
        authorization_data: Some(vec![AuthorizationDataElement {
            ad_type: 1,
            ad_data: OctetString::from(vec![0x30, 0x00]),
        }]),
    };
    roundtrip(&etp);
}

// --- KrbCredInfo roundtrip ---

#[test]
fn test_krb_cred_info_roundtrip() {
    let info = KrbCredInfo {
        key: make_encryption_key(),
        prealm: Some(make_realm()),
        pname: Some(make_principal()),
        flags: Some(make_bitstring_flags()),
        authtime: Some(make_time()),
        starttime: None,
        endtime: Some(make_time()),
        renew_till: None,
        srealm: Some(make_realm()),
        sname: Some(make_srv_principal()),
        caddr: None,
    };
    roundtrip(&info);
}

// --- EncKrbCredPart roundtrip ---

#[test]
fn test_enc_krb_cred_part_roundtrip() {
    let part = EncKrbCredPart {
        ticket_info: vec![KrbCredInfo {
            key: make_encryption_key(),
            prealm: None,
            pname: None,
            flags: None,
            authtime: None,
            starttime: None,
            endtime: None,
            renew_till: None,
            srealm: None,
            sname: None,
            caddr: None,
        }],
        nonce: Some(42),
        timestamp: Some(make_time()),
        usec: Some(0),
        s_address: None,
        r_address: None,
    };
    roundtrip(&part);
}

// --- KrbFastResponse roundtrip ---

#[test]
fn test_krb_fast_response_roundtrip() {
    let resp = KrbFastResponse {
        padata: vec![PaData {
            padata_type: 136,
            padata_value: OctetString::from(vec![0x01]),
        }],
        strengthen_key: Some(make_encryption_key()),
        finished: Some(KrbFastFinished {
            timestamp: make_time(),
            usec: 0,
            crealm: make_realm(),
            cname: make_principal(),
            ticket_checksum: make_checksum(),
        }),
        nonce: 99,
    };
    roundtrip(&resp);
}

// --- Additional enum conversion tests ---

#[test]
fn test_message_type_conversion() {
    assert_eq!(MessageType::try_from(10), Ok(MessageType::AsReq));
    assert_eq!(MessageType::try_from(30), Ok(MessageType::KrbError));
    assert_eq!(MessageType::try_from(99), Err(99));
}

#[test]
fn test_pa_data_type_conversion() {
    assert_eq!(PaDataType::try_from(2), Ok(PaDataType::EncTimestamp));
    assert_eq!(PaDataType::try_from(19), Ok(PaDataType::EtypeInfo2));
    assert_eq!(PaDataType::try_from(128), Ok(PaDataType::PaPacRequest));
    assert_eq!(PaDataType::try_from(999), Err(999));
}

#[test]
fn test_auth_data_type_conversion() {
    assert_eq!(AuthDataType::try_from(1), Ok(AuthDataType::IfRelevant));
    assert_eq!(AuthDataType::try_from(128), Ok(AuthDataType::Win2kPac));
}

#[test]
fn test_lr_type_conversion() {
    assert_eq!(LrType::try_from(6), Ok(LrType::PasswordExpires));
    assert_eq!(LrType::try_from(100), Err(100));
}
