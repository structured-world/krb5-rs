//! AS exchange state machine.
//!
//! Implements the step-based pattern from MIT krb5's `krb5_init_creds_step()`.
//! The caller drives the loop and controls transport — this module only
//! produces outbound messages and consumes inbound responses.

use std::time::Duration;

use chrono::{FixedOffset, Utc};
use rasn::types::GeneralString;
use zeroize::Zeroizing;

use crate::crypto::{find_etype, key_usage};
use crate::types::{
    AsRep, AsReq, EncAsRepPart, EncKdcRepPart, EncTgsRepPart, KdcOptions, KdcRep, KdcReq,
    KdcReqBody, KerberosFlags, KerberosTime, KrbErrorMsg, PaData, PaDataType, PrincipalName,
};
use crate::Krb5Error;

use super::credential::{Credential, TicketTimes};
use super::preauth::{
    build_pa_enc_timestamp, build_pa_pac_request, default_salt, extract_preauth_hint, PreauthHint,
};
use super::validate::{validate_as_reply, DEFAULT_MAX_CLOCK_SKEW};

/// KDC error codes relevant to AS exchange.
const KDC_ERR_PREAUTH_REQUIRED: i32 = 25;
const KRB_ERR_RESPONSE_TOO_BIG: i32 = 52;
const KDC_ERR_WRONG_REALM: i32 = 68;

/// Maximum pre-authentication loop iterations (matches MIT krb5).
const MAX_PREAUTH_LOOPS: u32 = 16;

/// Configuration for an AS exchange.
#[derive(Debug, Clone)]
pub struct AsExchangeConfig {
    /// Client principal name.
    pub client: PrincipalName,
    /// Kerberos realm.
    pub realm: String,
    /// Preferred encryption types (in order). Default: [AES-256, AES-128].
    pub etypes: Vec<i32>,
    /// KDC options flags.
    pub kdc_options: KerberosFlags<KdcOptions>,
    /// Requested ticket lifetime. Default: 10 hours.
    pub tkt_lifetime: Duration,
    /// Requested renewable lifetime. Default: 7 days. Set to zero for non-renewable.
    pub renew_lifetime: Duration,
    /// Whether to request PAC inclusion (for AD environments). Default: true.
    pub request_pac: bool,
    /// Maximum allowed clock skew. Default: 5 minutes.
    pub max_clock_skew: Duration,
}

impl Default for AsExchangeConfig {
    fn default() -> Self {
        Self {
            client: PrincipalName::new_principal(""),
            realm: String::new(),
            etypes: vec![18, 17], // AES-256, AES-128
            kdc_options: KerberosFlags::new(
                KdcOptions::FORWARDABLE | KdcOptions::RENEWABLE | KdcOptions::CANONICALIZE,
            ),
            tkt_lifetime: Duration::from_secs(10 * 3600), // 10 hours
            renew_lifetime: Duration::from_secs(7 * 24 * 3600), // 7 days
            request_pac: true,
            max_clock_skew: DEFAULT_MAX_CLOCK_SKEW,
        }
    }
}

impl AsExchangeConfig {
    /// Create a config for the given principal and realm with defaults.
    pub fn new(client: PrincipalName, realm: impl Into<String>) -> Self {
        Self {
            client,
            realm: realm.into(),
            ..Default::default()
        }
    }
}

/// Result of a single `step()` call.
#[derive(Debug)]
pub enum StepResult {
    /// Send this DER-encoded message to the KDC for the given realm.
    SendToKdc {
        /// DER-encoded AS-REQ.
        data: Vec<u8>,
        /// Realm to send to (for KDC discovery).
        realm: String,
    },
    /// Exchange finished successfully. Call `credential()` to extract result.
    Complete,
}

/// Internal state of the AS exchange.
enum AsState {
    /// Build and send the initial AS-REQ (possibly without preauth).
    Initial,
    /// Waiting for KDC response (may transition to Preauth or Complete).
    AwaitReply,
    /// Exchange complete.
    Complete,
}

/// Step-based AS exchange state machine.
///
/// # Usage
///
/// ```rust,ignore
/// let config = AsExchangeConfig::new(principal, "EXAMPLE.COM");
/// let mut exchange = AsExchange::new(config, "password");
/// let mut kdc_reply = Vec::new();
///
/// loop {
///     match exchange.step(&kdc_reply)? {
///         StepResult::SendToKdc { data, realm } => {
///             kdc_reply = transport.send(&realm, &data).await?;
///         }
///         StepResult::Complete => break,
///     }
/// }
///
/// let cred = exchange.credential()?;
/// ```
pub struct AsExchange {
    state: AsState,
    config: AsExchangeConfig,
    password: Zeroizing<String>,
    nonce: u32,
    /// The most recent AS-REQ body (for validation on reply).
    last_req_body: Option<KdcReqBody>,
    /// Loop counter to prevent infinite preauth loops.
    loop_count: u32,
    /// Output credential.
    credential: Option<Credential>,
}

impl AsExchange {
    /// Create a new AS exchange.
    pub fn new(config: AsExchangeConfig, password: impl Into<String>) -> Self {
        Self {
            state: AsState::Initial,
            config,
            password: Zeroizing::new(password.into()),
            nonce: 0,
            last_req_body: None,
            loop_count: 0,
            credential: None,
        }
    }

    /// Advance the state machine.
    ///
    /// On the first call, pass an empty slice. On subsequent calls, pass
    /// the KDC's response bytes.
    pub fn step(&mut self, kdc_reply: &[u8]) -> Result<StepResult, Krb5Error> {
        match self.state {
            AsState::Initial => {
                // First call — build initial AS-REQ (no preauth)
                let (as_req_der, req_body) = self.build_as_req(None)?;
                self.last_req_body = Some(req_body);
                self.state = AsState::AwaitReply;
                Ok(StepResult::SendToKdc {
                    data: as_req_der,
                    realm: self.config.realm.clone(),
                })
            }
            AsState::AwaitReply => {
                // Process KDC response
                self.process_kdc_reply(kdc_reply)
            }
            AsState::Complete => Ok(StepResult::Complete),
        }
    }

    /// Extract the credential after successful completion.
    pub fn credential(&self) -> Result<&Credential, Krb5Error> {
        self.credential
            .as_ref()
            .ok_or(Krb5Error::ReplyValidation("exchange not complete"))
    }

    /// Process a KDC response.
    fn process_kdc_reply(&mut self, kdc_reply: &[u8]) -> Result<StepResult, Krb5Error> {
        if kdc_reply.is_empty() {
            return Err(Krb5Error::ReplyValidation("empty KDC reply"));
        }

        self.loop_count += 1;
        if self.loop_count > MAX_PREAUTH_LOOPS {
            return Err(Krb5Error::PreauthLoopExceeded(MAX_PREAUTH_LOOPS));
        }

        // Try to decode as AS-REP first
        if let Ok(as_rep) = rasn::der::decode::<AsRep>(kdc_reply) {
            return self.process_as_rep(as_rep);
        }

        // Try to decode as KRB-ERROR
        let krb_error: KrbErrorMsg = rasn::der::decode(kdc_reply)?;

        match krb_error.error_code {
            KDC_ERR_PREAUTH_REQUIRED => {
                // Extract preauth hints from e-data
                let e_data = krb_error.e_data.as_ref().ok_or(Krb5Error::NoCommonEtype)?;
                let hint = extract_preauth_hint(e_data.as_ref(), &self.config.etypes)?;

                // Build AS-REQ with preauth
                let pa_timestamp = self.build_preauth_padata(&hint)?;
                let (as_req_der, req_body) = self.build_as_req(Some(pa_timestamp))?;
                self.last_req_body = Some(req_body);
                // Stay in AwaitReply state for next response
                Ok(StepResult::SendToKdc {
                    data: as_req_der,
                    realm: self.config.realm.clone(),
                })
            }
            KRB_ERR_RESPONSE_TOO_BIG => {
                // Signal caller to retry over TCP by re-emitting the last request.
                // The caller should detect this error and switch transport.
                Err(Krb5Error::from_error_msg(krb_error))
            }
            KDC_ERR_WRONG_REALM => {
                // Client realm referral — KDC tells us the correct realm.
                // Update realm from the error's crealm field and restart.
                if let Some(ref crealm) = krb_error.crealm {
                    let new_realm = String::from_utf8_lossy(crealm.as_bytes()).to_string();
                    if new_realm != self.config.realm {
                        self.config.realm = new_realm;
                        // Restart: build a new initial AS-REQ for the new realm
                        let (as_req_der, req_body) = self.build_as_req(None)?;
                        self.last_req_body = Some(req_body);
                        return Ok(StepResult::SendToKdc {
                            data: as_req_der,
                            realm: self.config.realm.clone(),
                        });
                    }
                }
                // If no crealm in error or same realm, propagate error
                Err(Krb5Error::from_error_msg(krb_error))
            }
            _ => {
                // Other KDC error — propagate
                Err(Krb5Error::from_error_msg(krb_error))
            }
        }
    }

    /// Build an AS-REQ message. Returns (DER bytes, request body for validation).
    fn build_as_req(
        &mut self,
        preauth_padata: Option<Vec<PaData>>,
    ) -> Result<(Vec<u8>, KdcReqBody), Krb5Error> {
        // Generate random nonce
        self.nonce = rand::random();

        let realm = GeneralString::from_bytes(self.config.realm.as_bytes())
            .map_err(|e| Krb5Error::Crypto(format!("invalid realm string: {e}")))?;

        // Build server principal: krbtgt/REALM
        let sname = PrincipalName::new_srv_inst("krbtgt", &self.config.realm);

        // Compute till time using chrono
        let now = now_kerberos();
        let till_secs = self.config.tkt_lifetime.as_secs() as i64;
        let till = now + chrono::Duration::seconds(till_secs);

        // Compute rtime if renewable
        let rtime = if self.config.kdc_options.contains(KdcOptions::RENEWABLE) {
            let rtime_secs = self.config.renew_lifetime.as_secs() as i64;
            Some(now + chrono::Duration::seconds(rtime_secs))
        } else {
            None
        };

        let req_body = KdcReqBody {
            kdc_options: self.config.kdc_options,
            cname: Some(self.config.client.clone()),
            realm: realm.clone(),
            sname: Some(sname),
            from: None,
            till,
            rtime,
            nonce: self.nonce,
            etype: self.config.etypes.clone(),
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        };

        // Build padata list
        let mut padata: Vec<PaData> = Vec::new();

        // Add preauth padata if provided
        if let Some(pa_list) = preauth_padata {
            padata.extend(pa_list);
        }

        // Add PA-PAC-REQUEST if configured
        if self.config.request_pac {
            padata.push(build_pa_pac_request(true)?);
        }

        let padata_opt = if padata.is_empty() {
            None
        } else {
            Some(padata)
        };

        let kdc_req = KdcReq {
            pvno: 5,
            msg_type: 10, // AS-REQ
            padata: padata_opt,
            req_body: req_body.clone(),
        };

        let as_req = AsReq(kdc_req);
        let der = rasn::der::encode(&as_req)?;

        Ok((der, req_body))
    }

    /// Build PA-ENC-TIMESTAMP and return as padata vec.
    fn build_preauth_padata(&self, hint: &PreauthHint) -> Result<Vec<PaData>, Krb5Error> {
        let now = now_kerberos();
        let usec = Utc::now().timestamp_subsec_micros() as i32;

        // Compute salt: use hint salt, or compute default
        let salt = if hint.salt.is_empty() {
            let components: Vec<&[u8]> = self
                .config
                .client
                .name_string
                .iter()
                .map(|s| s.as_bytes())
                .collect();
            default_salt(&self.config.realm, &components)
        } else {
            hint.salt.clone()
        };

        let pa_timestamp = build_pa_enc_timestamp(
            self.password.as_bytes(),
            &salt,
            hint.s2kparams.as_deref(),
            hint.etype,
            now,
            Some(usec),
        )?;

        Ok(vec![pa_timestamp])
    }

    /// Process a successful AS-REP: decrypt enc-part, validate, build credential.
    fn process_as_rep(&mut self, as_rep: AsRep) -> Result<StepResult, Krb5Error> {
        let rep = &as_rep.0;

        // Determine encryption type from enc-part
        let etype = rep.enc_part.etype;
        let profile = find_etype(etype).map_err(|_| Krb5Error::UnsupportedEtype(etype))?;

        // Derive key from password
        let salt = self.compute_reply_salt(rep);
        let key = profile
            .string_to_key(self.password.as_bytes(), &salt, None)
            .map_err(|e| Krb5Error::Crypto(e.to_string()))?;

        // Decrypt EncAsRepPart (key usage 3)
        let plaintext = profile
            .decrypt(
                &key,
                key_usage::AS_REP_ENCPART,
                rep.enc_part.cipher.as_ref(),
            )
            .map_err(|_| Krb5Error::DecryptionFailed)?;

        // Try EncAsRepPart (APPLICATION 25) first, then EncTgsRepPart (APPLICATION 26)
        // Some KDCs (Heimdal) use APPLICATION 26 for AS-REP enc-part
        let enc_part: EncKdcRepPart = match rasn::der::decode::<EncAsRepPart>(&plaintext) {
            Ok(enc_as) => enc_as.0,
            Err(_) => {
                let enc_tgs: EncTgsRepPart = rasn::der::decode(&plaintext)?;
                enc_tgs.0
            }
        };

        // Validate the reply
        let now = now_kerberos();
        let canonicalize = self.config.kdc_options.contains(KdcOptions::CANONICALIZE);
        let req_body = self
            .last_req_body
            .as_ref()
            .ok_or(Krb5Error::ReplyValidation("no request body saved"))?;

        validate_as_reply(
            self.nonce,
            req_body,
            rep,
            &enc_part,
            canonicalize,
            self.config.max_clock_skew,
            now,
        )?;

        // Build credential
        let credential = Credential {
            client: rep.cname.clone(),
            crealm: String::from_utf8_lossy(rep.crealm.as_bytes()).to_string(),
            server: enc_part.sname.clone(),
            srealm: String::from_utf8_lossy(enc_part.srealm.as_bytes()).to_string(),
            session_key: enc_part.key.clone(),
            times: TicketTimes {
                authtime: enc_part.authtime,
                starttime: enc_part.starttime,
                endtime: enc_part.endtime,
                renew_till: enc_part.renew_till,
            },
            ticket: rep.ticket.clone(),
            flags: enc_part.flags,
            addresses: enc_part.caddr.clone(),
            authdata: None,
        };

        self.credential = Some(credential);
        self.state = AsState::Complete;
        Ok(StepResult::Complete)
    }

    /// Compute salt for reply key derivation.
    fn compute_reply_salt(&self, rep: &KdcRep) -> Vec<u8> {
        // Try to extract salt from reply padata (PA-ETYPE-INFO2)
        if let Some(ref padata) = rep.padata {
            for pa in padata {
                if pa.padata_type == PaDataType::EtypeInfo2 as i32 {
                    if let Ok(entries) = rasn::der::decode::<Vec<crate::types::EtypeInfo2Entry>>(
                        pa.padata_value.as_ref(),
                    ) {
                        for entry in &entries {
                            if entry.etype == rep.enc_part.etype {
                                if let Some(ref s) = entry.salt {
                                    return s.as_bytes().to_vec();
                                }
                            }
                        }
                    }
                }
            }
        }

        // Default salt: REALM + principal components
        let components: Vec<&[u8]> = self
            .config
            .client
            .name_string
            .iter()
            .map(|s| s.as_bytes())
            .collect();
        default_salt(&self.config.realm, &components)
    }
}

/// Get current time as KerberosTime (chrono DateTime<FixedOffset> in UTC).
fn now_kerberos() -> KerberosTime {
    Utc::now().with_timezone(&FixedOffset::east_opt(0).expect("UTC offset"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = AsExchangeConfig::new(PrincipalName::new_principal("user"), "EXAMPLE.COM");
        assert_eq!(config.realm, "EXAMPLE.COM");
        assert_eq!(config.etypes, vec![18, 17]);
        assert!(config.kdc_options.contains(KdcOptions::FORWARDABLE));
        assert!(config.kdc_options.contains(KdcOptions::RENEWABLE));
        assert!(config.kdc_options.contains(KdcOptions::CANONICALIZE));
        assert!(config.request_pac);
        assert_eq!(config.tkt_lifetime, Duration::from_secs(36000));
        assert_eq!(config.renew_lifetime, Duration::from_secs(604800));
    }

    #[test]
    fn test_exchange_initial_step_produces_as_req() {
        let config = AsExchangeConfig::new(PrincipalName::new_principal("testuser"), "EXAMPLE.COM");
        let mut exchange = AsExchange::new(config, "password");

        let result = exchange.step(&[]).expect("initial step should succeed");
        match result {
            StepResult::SendToKdc { data, realm } => {
                assert_eq!(realm, "EXAMPLE.COM");
                // Should be a valid AS-REQ
                let as_req: AsReq = rasn::der::decode(&data).expect("should decode as AS-REQ");
                assert_eq!(as_req.0.pvno, 5);
                assert_eq!(as_req.0.msg_type, 10);
                assert_eq!(
                    as_req.0.req_body.realm,
                    GeneralString::from_bytes(b"EXAMPLE.COM").expect("realm")
                );
                // Should have PA-PAC-REQUEST in padata
                let padata = as_req.0.padata.expect("should have padata");
                assert!(padata
                    .iter()
                    .any(|pa| pa.padata_type == PaDataType::PaPacRequest as i32));
                // Nonce should be set
                assert_ne!(as_req.0.req_body.nonce, 0);
                // Etypes should match config
                assert_eq!(as_req.0.req_body.etype, vec![18, 17]);
            }
            StepResult::Complete => panic!("should not be complete on first step"),
        }
    }

    #[test]
    fn test_exchange_preauth_required_produces_enc_timestamp() {
        let config = AsExchangeConfig::new(PrincipalName::new_principal("testuser"), "EXAMPLE.COM");
        let mut exchange = AsExchange::new(config, "password");

        // Initial step
        let _result = exchange.step(&[]).expect("initial step");

        // Build a PREAUTH_REQUIRED error response
        let error_reply = build_preauth_required_error();
        let result = exchange
            .step(&error_reply)
            .expect("should handle PREAUTH_REQUIRED");

        match result {
            StepResult::SendToKdc { data, realm } => {
                assert_eq!(realm, "EXAMPLE.COM");
                // Should be an AS-REQ with PA-ENC-TIMESTAMP
                let as_req: AsReq = rasn::der::decode(&data).expect("should decode as AS-REQ");
                let padata = as_req.0.padata.expect("should have padata");
                assert!(padata
                    .iter()
                    .any(|pa| pa.padata_type == PaDataType::EncTimestamp as i32));
            }
            StepResult::Complete => panic!("should not be complete after preauth required"),
        }
    }

    #[test]
    fn test_exchange_loop_count_exceeded() {
        let config = AsExchangeConfig::new(PrincipalName::new_principal("testuser"), "EXAMPLE.COM");
        let mut exchange = AsExchange::new(config, "password");
        // Set initial step so we're in AwaitReply
        let _result = exchange.step(&[]).expect("initial step");
        exchange.loop_count = MAX_PREAUTH_LOOPS;

        let error_reply = build_preauth_required_error();
        let result = exchange.step(&error_reply);
        assert!(matches!(result, Err(Krb5Error::PreauthLoopExceeded(_))));
    }

    #[test]
    fn test_exchange_empty_reply_rejected() {
        let config = AsExchangeConfig::new(PrincipalName::new_principal("testuser"), "EXAMPLE.COM");
        let mut exchange = AsExchange::new(config, "password");
        let _result = exchange.step(&[]).expect("initial step");

        let result = exchange.step(&[]);
        assert!(matches!(result, Err(Krb5Error::ReplyValidation(_))));
    }

    #[test]
    fn test_exchange_response_too_big_propagates_error() {
        let config = AsExchangeConfig::new(PrincipalName::new_principal("testuser"), "EXAMPLE.COM");
        let mut exchange = AsExchange::new(config, "password");
        let _result = exchange.step(&[]).expect("initial step");

        let error_reply = build_krb_error(KRB_ERR_RESPONSE_TOO_BIG, None);
        let result = exchange.step(&error_reply);
        assert!(matches!(result, Err(Krb5Error::KdcError(_))));
    }

    #[test]
    fn test_exchange_wrong_realm_redirects() {
        let config = AsExchangeConfig::new(PrincipalName::new_principal("testuser"), "EXAMPLE.COM");
        let mut exchange = AsExchange::new(config, "password");
        let _result = exchange.step(&[]).expect("initial step");

        let error_reply = build_krb_error(KDC_ERR_WRONG_REALM, Some("OTHER.REALM"));
        let result = exchange.step(&error_reply).expect("should redirect");
        match result {
            StepResult::SendToKdc { realm, data } => {
                assert_eq!(realm, "OTHER.REALM");
                // Verify the new AS-REQ targets the new realm
                let as_req: AsReq = rasn::der::decode(&data).expect("decode AS-REQ");
                assert_eq!(
                    as_req.0.req_body.realm,
                    GeneralString::from_bytes(b"OTHER.REALM").expect("realm")
                );
            }
            StepResult::Complete => panic!("should redirect, not complete"),
        }
        assert_eq!(exchange.config.realm, "OTHER.REALM");
    }

    #[test]
    fn test_exchange_wrong_realm_same_realm_propagates() {
        let config = AsExchangeConfig::new(PrincipalName::new_principal("testuser"), "EXAMPLE.COM");
        let mut exchange = AsExchange::new(config, "password");
        let _result = exchange.step(&[]).expect("initial step");

        // WRONG_REALM but crealm == current realm → propagate error
        let error_reply = build_krb_error(KDC_ERR_WRONG_REALM, Some("EXAMPLE.COM"));
        let result = exchange.step(&error_reply);
        assert!(matches!(result, Err(Krb5Error::KdcError(_))));
    }

    #[test]
    fn test_exchange_kdc_error_propagated() {
        let config = AsExchangeConfig::new(PrincipalName::new_principal("testuser"), "EXAMPLE.COM");
        let mut exchange = AsExchange::new(config, "password");
        let _result = exchange.step(&[]).expect("initial step");

        // C_PRINCIPAL_UNKNOWN (6)
        let error_reply = build_krb_error(6, None);
        let result = exchange.step(&error_reply);
        match result {
            Err(Krb5Error::KdcError(err)) => {
                assert_eq!(err.error_code, 6);
            }
            other => panic!("expected KdcError, got: {other:?}"),
        }
    }

    /// Helper: build a DER-encoded KRB-ERROR with the given error code.
    fn build_krb_error(error_code: i32, crealm: Option<&str>) -> Vec<u8> {
        let now = now_kerberos();
        let krb_error = KrbErrorMsg {
            pvno: 5,
            msg_type: 30,
            ctime: None,
            cusec: None,
            stime: now,
            susec: 0,
            error_code,
            crealm: crealm.map(|r| GeneralString::from_bytes(r.as_bytes()).expect("crealm")),
            cname: None,
            realm: GeneralString::from_bytes(b"EXAMPLE.COM").expect("realm"),
            sname: PrincipalName::new_srv_inst("krbtgt", "EXAMPLE.COM"),
            e_text: None,
            e_data: None,
        };
        rasn::der::encode(&krb_error).expect("encode KRB-ERROR")
    }

    /// Helper: build a DER-encoded KRB-ERROR with PREAUTH_REQUIRED and PA-ETYPE-INFO2.
    fn build_preauth_required_error() -> Vec<u8> {
        use crate::types::EtypeInfo2Entry;

        let entries = vec![EtypeInfo2Entry {
            etype: 18,
            salt: Some(GeneralString::from_bytes(b"EXAMPLE.COMtestuser").expect("salt")),
            s2kparams: None,
        }];
        let etype_info2_der = rasn::der::encode(&entries).expect("encode ETYPE-INFO2");

        let method_data = vec![PaData {
            padata_type: PaDataType::EtypeInfo2 as i32,
            padata_value: etype_info2_der.into(),
        }];
        let e_data = rasn::der::encode(&method_data).expect("encode METHOD-DATA");

        let now = now_kerberos();
        let krb_error = KrbErrorMsg {
            pvno: 5,
            msg_type: 30,
            ctime: None,
            cusec: None,
            stime: now,
            susec: 0,
            error_code: KDC_ERR_PREAUTH_REQUIRED,
            crealm: None,
            cname: None,
            realm: GeneralString::from_bytes(b"EXAMPLE.COM").expect("realm"),
            sname: PrincipalName::new_srv_inst("krbtgt", "EXAMPLE.COM"),
            e_text: None,
            e_data: Some(e_data.into()),
        };
        rasn::der::encode(&krb_error).expect("encode KRB-ERROR")
    }
}
