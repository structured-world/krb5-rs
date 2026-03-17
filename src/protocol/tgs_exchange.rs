//! TGS exchange state machine.
//!
//! Implements the step-based pattern for obtaining service tickets using
//! a previously acquired TGT. Follows MIT krb5's state machine design
//! with cross-realm referral support.

use std::time::Duration;

use crate::crypto::{find_etype, key_usage};
use crate::types::{
    ApOptions, ApReq, Authenticator, Checksum, EncKdcRepPart, EncTgsRepPart, EncryptedData,
    EncryptionKey, KdcOptions, KdcReq, KdcReqBody, KerberosFlags, KerberosTime, KrbErrorMsg,
    PaData, PrincipalName, TgsRep, TgsReq, TicketFlags,
};
use crate::Krb5Error;
use chrono::{FixedOffset, Timelike, Utc};
use rasn::types::GeneralString;
use zeroize::Zeroizing;

use super::credential::{Credential, TicketTimes};
use super::error_codes::ErrorCode;
use super::validate::DEFAULT_MAX_CLOCK_SKEW;

/// Maximum cross-realm referral hops (matches MIT's KRB5_REFERRAL_MAXHOPS).
const MAX_REFERRAL_HOPS: u32 = 10;

/// KDC error codes used in match patterns.
const KDC_ERR_S_PRINCIPAL_UNKNOWN: i32 = ErrorCode::SPrincipalUnknown as i32;
const KRB_ERR_RESPONSE_TOO_BIG: i32 = ErrorCode::ResponseTooBig as i32;

/// PA-DATA type for PA-TGS-REQ (RFC 4120 §7.5.1).
const PA_TGS_REQ: i32 = 1;

/// PA-PAC-OPTIONS padata type (MS-KILE §2.2.10).
const PA_PAC_OPTIONS: i32 = 167;

/// PA-PAC-OPTIONS flags: Branch Aware (bit 1 = 0x40000000 per MS-KILE §2.2.10).
/// This matches what sspi-rs and Windows clients send for AD interop.
/// Claims (bit 0) would be 0x80000000 — not set here.
const PA_PAC_OPTIONS_FLAGS: [u8; 4] = [0x40, 0x00, 0x00, 0x00];

/// UTC offset for KerberosTime construction.
const UTC_OFFSET: FixedOffset = match FixedOffset::east_opt(0) {
    Some(o) => o,
    None => panic!("UTC offset 0 is always valid"),
};

/// Options controlling TGS exchange behavior.
#[derive(Debug, Clone)]
pub struct TgsOptions {
    /// Whether to attempt referral following (CANONICALIZE flag).
    /// Default: true.
    pub canonicalize: bool,
    /// Whether to request forwardable tickets. Default: true.
    pub forwardable: bool,
    /// Preferred encryption types. Default: [AES-256, AES-128].
    pub etypes: Vec<i32>,
    /// Maximum allowed clock skew. Default: 5 minutes.
    pub max_clock_skew: Duration,
    /// Whether to include PA-PAC-OPTIONS (claims-aware). Default: true.
    pub pac_options: bool,
}

impl Default for TgsOptions {
    fn default() -> Self {
        Self {
            canonicalize: true,
            forwardable: true,
            etypes: vec![18, 17], // AES-256, AES-128
            max_clock_skew: DEFAULT_MAX_CLOCK_SKEW,
            pac_options: true,
        }
    }
}

/// Result of a single `step()` call.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum TgsStepResult {
    /// Send this DER-encoded TGS-REQ to the KDC for the given realm.
    SendToKdc {
        /// DER-encoded TGS-REQ.
        data: Vec<u8>,
        /// Realm to send to.
        realm: String,
    },
    /// Resend the same request over TCP (response too big for UDP).
    RetryTcp {
        /// DER-encoded TGS-REQ (same bytes).
        data: Vec<u8>,
        /// Realm.
        realm: String,
    },
    /// Exchange complete. Call `credential()` to extract result.
    Complete,
}

/// Internal state of the TGS exchange.
enum TgsState {
    /// Initial state — build and send first TGS-REQ.
    Begin,
    /// Waiting for KDC response.
    AwaitReply {
        /// Which logical state to resume after getting the reply.
        resume: ResumeState,
    },
    /// Exchange complete.
    Complete,
}

/// Which state to resume processing after receiving a KDC reply.
#[derive(Debug, Clone)]
enum ResumeState {
    /// Resume referral processing.
    Referrals {
        realms_seen: Vec<String>,
        referral_count: u32,
    },
    /// Resume non-referral processing.
    NonReferral,
}

/// Step-based TGS exchange state machine.
///
/// # Usage
///
/// ```rust,ignore
/// let mut exchange = TgsExchange::new(tgt, target_service, TgsOptions::default());
/// let mut kdc_reply = Vec::new();
///
/// loop {
///     match exchange.step(&kdc_reply)? {
///         TgsStepResult::SendToKdc { data, realm }
///         | TgsStepResult::RetryTcp { data, realm } => {
///             kdc_reply = transport.send(&realm, &data).await?;
///         }
///         TgsStepResult::Complete => break,
///     }
/// }
///
/// let service_cred = exchange.credential()?;
/// ```
pub struct TgsExchange {
    state: TgsState,
    /// TGT currently used for requests (may change during referrals).
    cur_tgt: Credential,
    /// Target service principal.
    target_server: PrincipalName,
    /// Options controlling behavior.
    options: TgsOptions,
    /// Subkey generated for the most recent request.
    subkey: Option<EncryptionKey>,
    /// Nonce for the most recent request.
    nonce: u32,
    /// Most recent DER-encoded TGS-REQ (for RetryTcp re-emit).
    last_req_bytes: Vec<u8>,
    /// Realm we last sent to.
    last_realm: String,
    /// Output credential.
    credential: Option<Credential>,
    /// Whether this was a first referral attempt (for fallback to NonReferral).
    first_referral_attempt: bool,
}

impl TgsExchange {
    /// Create a new TGS exchange.
    ///
    /// `tgt` is the TGT credential from a prior AS exchange.
    /// `target` is the service principal to get a ticket for.
    pub fn new(tgt: Credential, target: PrincipalName, options: TgsOptions) -> Self {
        Self {
            state: TgsState::Begin,
            cur_tgt: tgt,
            target_server: target,
            options,
            subkey: None,
            nonce: 0,
            last_req_bytes: Vec::new(),
            last_realm: String::new(),
            credential: None,
            first_referral_attempt: true,
        }
    }

    /// Advance the state machine.
    ///
    /// On the first call, pass an empty slice. On subsequent calls, pass
    /// the KDC's response bytes.
    pub fn step(&mut self, kdc_reply: &[u8]) -> Result<TgsStepResult, Krb5Error> {
        match &self.state {
            TgsState::Begin => self.begin(),
            TgsState::AwaitReply { .. } => self.process_reply(kdc_reply),
            TgsState::Complete => Ok(TgsStepResult::Complete),
        }
    }

    /// Extract the credential after successful completion.
    pub fn credential(&self) -> Result<&Credential, Krb5Error> {
        self.credential
            .as_ref()
            .ok_or(Krb5Error::ReplyValidation("TGS exchange not complete"))
    }

    /// Determine the realm to send TGS-REQs to.
    ///
    /// For `krbtgt/X@Y`, the target realm is X (the realm this TGT grants
    /// access to). For a home-realm TGT `krbtgt/MINE@MINE`, this is MINE.
    /// For a cross-realm TGT `krbtgt/OTHER@MINE`, this is OTHER.
    fn tgt_target_realm(&self) -> String {
        let sname = &self.cur_tgt.server;
        if sname.name_type == 2
            && sname.name_string.len() == 2
            && sname.name_string[0].as_bytes() == b"krbtgt"
        {
            String::from_utf8_lossy(sname.name_string[1].as_bytes()).to_string()
        } else {
            // Fallback to srealm for non-krbtgt credentials
            self.cur_tgt.srealm.clone()
        }
    }

    /// Begin the exchange — send the first TGS-REQ.
    fn begin(&mut self) -> Result<TgsStepResult, Krb5Error> {
        if self.options.canonicalize {
            // Start with referral path
            let realm = self.tgt_target_realm();
            let realms_seen = vec![realm.clone()];
            let tgs_req = self.build_tgs_req(true)?;
            self.state = TgsState::AwaitReply {
                resume: ResumeState::Referrals {
                    realms_seen,
                    referral_count: 0,
                },
            };
            self.last_realm = realm.clone();
            Ok(TgsStepResult::SendToKdc {
                data: tgs_req,
                realm,
            })
        } else {
            // Direct non-referral request
            let realm = self.tgt_target_realm();
            let tgs_req = self.build_tgs_req(false)?;
            self.state = TgsState::AwaitReply {
                resume: ResumeState::NonReferral,
            };
            self.last_realm = realm.clone();
            Ok(TgsStepResult::SendToKdc {
                data: tgs_req,
                realm,
            })
        }
    }

    /// Process a KDC reply.
    fn process_reply(&mut self, kdc_reply: &[u8]) -> Result<TgsStepResult, Krb5Error> {
        if kdc_reply.is_empty() {
            return Err(Krb5Error::ReplyValidation("empty KDC reply"));
        }

        // Extract resume state before processing
        let resume = match &self.state {
            TgsState::AwaitReply { resume } => resume.clone(),
            _ => {
                return Err(Krb5Error::ReplyValidation(
                    "process_reply called in wrong state",
                ))
            }
        };

        // Try to decode as TGS-REP first
        if let Ok(tgs_rep) = rasn::der::decode::<TgsRep>(kdc_reply) {
            if tgs_rep.0.pvno != 5 || tgs_rep.0.msg_type != 13 {
                return Err(Krb5Error::ReplyValidation("invalid TGS-REP pvno/msg_type"));
            }
            let step = self.process_tgs_rep(tgs_rep, resume)?;
            // Only disable fallback after successful decrypt/validation —
            // a malformed TGS-REP must not permanently kill the fallback path.
            self.first_referral_attempt = false;
            return Ok(step);
        }

        // Try to decode as KRB-ERROR
        let krb_error: KrbErrorMsg = rasn::der::decode(kdc_reply)?;
        if krb_error.pvno != 5 || krb_error.msg_type != 30 {
            return Err(Krb5Error::ReplyValidation(
                "invalid KRB-ERROR pvno/msg_type",
            ));
        }

        match krb_error.error_code {
            KRB_ERR_RESPONSE_TOO_BIG => {
                // Re-emit the same request for TCP retry
                self.state = TgsState::AwaitReply { resume };
                Ok(TgsStepResult::RetryTcp {
                    data: self.last_req_bytes.clone(),
                    realm: self.last_realm.clone(),
                })
            }
            KDC_ERR_S_PRINCIPAL_UNKNOWN
                if self.first_referral_attempt
                    && matches!(resume, ResumeState::Referrals { .. }) =>
            {
                // Fallback to non-referral only when in referral mode.
                // Resend to the same KDC that rejected the request.
                self.first_referral_attempt = false;
                let realm = self.tgt_target_realm();
                let tgs_req = self.build_tgs_req(false)?;
                self.state = TgsState::AwaitReply {
                    resume: ResumeState::NonReferral,
                };
                self.last_realm = realm.clone();
                Ok(TgsStepResult::SendToKdc {
                    data: tgs_req,
                    realm,
                })
            }
            _ => Err(Krb5Error::from_error_msg(krb_error)),
        }
    }

    /// Process a successful TGS-REP.
    fn process_tgs_rep(
        &mut self,
        tgs_rep: TgsRep,
        resume: ResumeState,
    ) -> Result<TgsStepResult, Krb5Error> {
        let rep = &tgs_rep.0;

        // Decrypt EncTgsRepPart: try subkey first (usage 9), fallback to session key (usage 8)
        let enc_part = self.decrypt_tgs_rep_enc_part(rep)?;

        // Validate reply
        self.validate_tgs_reply(rep, &enc_part)?;

        // Check if this is a referral TGT or the actual service ticket
        let is_referral = self.is_referral_tgt(&enc_part);

        if is_referral {
            return self.handle_referral(rep, &enc_part, resume);
        }

        // Service ticket — build credential and complete
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
        self.state = TgsState::Complete;
        Ok(TgsStepResult::Complete)
    }

    /// Decrypt the EncTgsRepPart from a TGS-REP.
    ///
    /// Per RFC 4120 and MIT krb5: try subkey first (key usage 9),
    /// then fall back to TGT session key (key usage 8) for Heimdal interop.
    fn decrypt_tgs_rep_enc_part(
        &self,
        rep: &crate::types::KdcRep,
    ) -> Result<EncKdcRepPart, Krb5Error> {
        let etype = rep.enc_part.etype;
        let profile = find_etype(etype).map_err(|_| Krb5Error::UnsupportedEtype(etype))?;

        // Try subkey first (key usage 9) if we generated one
        if let Some(ref subkey) = self.subkey {
            if let Ok(plaintext) = profile.decrypt(
                subkey.key_bytes(),
                key_usage::TGS_REP_ENCPART_SUBKEY,
                rep.enc_part.cipher.as_ref(),
            ) {
                if let Ok(enc_part) = decode_enc_tgs_rep_part(&plaintext) {
                    return Ok(enc_part);
                }
            }
        }

        // Fallback: TGT session key (key usage 8)
        let plaintext = profile
            .decrypt(
                self.cur_tgt.session_key.key_bytes(),
                key_usage::TGS_REP_ENCPART_SESSKEY,
                rep.enc_part.cipher.as_ref(),
            )
            .map_err(|_| Krb5Error::DecryptionFailed)?;

        decode_enc_tgs_rep_part(&plaintext)
    }

    /// Validate TGS-REP fields.
    fn validate_tgs_reply(
        &self,
        rep: &crate::types::KdcRep,
        enc_part: &EncKdcRepPart,
    ) -> Result<(), Krb5Error> {
        // Client principal must match the TGT holder
        if rep.cname != self.cur_tgt.client {
            return Err(Krb5Error::ReplyValidation("client principal mismatch"));
        }
        if rep.crealm.as_bytes() != self.cur_tgt.crealm.as_bytes() {
            return Err(Krb5Error::ReplyValidation("client realm mismatch"));
        }

        // Nonce must match
        if enc_part.nonce != self.nonce {
            return Err(Krb5Error::ReplyValidation("nonce mismatch"));
        }

        // Ticket sname must match enc-part sname
        if rep.ticket.sname != enc_part.sname {
            return Err(Krb5Error::ReplyValidation(
                "ticket/enc-part server mismatch",
            ));
        }

        // Ticket realm must match enc-part srealm
        if rep.ticket.realm != enc_part.srealm {
            return Err(Krb5Error::ReplyValidation("ticket/enc-part realm mismatch"));
        }

        // For non-referral replies, the service principal must match what we requested.
        // Referral TGTs (krbtgt/OTHER-REALM) are validated in handle_referral() instead.
        if !self.is_referral_tgt(enc_part) && enc_part.sname != self.target_server {
            return Err(Krb5Error::ReplyValidation(
                "unexpected service principal in TGS-REP",
            ));
        }

        // Clock skew check on starttime/authtime
        let starttime = enc_part.starttime.as_ref().unwrap_or(&enc_part.authtime);
        let now = now_kerberos();
        let skew = time_diff(starttime, &now);
        if skew > self.options.max_clock_skew {
            return Err(Krb5Error::ClockSkew {
                max_skew: self.options.max_clock_skew,
            });
        }

        Ok(())
    }

    /// Check if a TGS-REP contains a referral TGT (krbtgt/OTHER-REALM).
    ///
    /// A referral TGT has sname = krbtgt/<REALM> where the realm differs
    /// from what we originally requested. If the response matches our
    /// target service principal, it's not a referral.
    fn is_referral_tgt(&self, enc_part: &EncKdcRepPart) -> bool {
        // Must be NT_SRV_INST with 2 components
        if enc_part.sname.name_type != 2 || enc_part.sname.name_string.len() != 2 {
            return false;
        }
        // First component must be "krbtgt"
        if enc_part.sname.name_string[0].as_bytes() != b"krbtgt" {
            return false;
        }
        // If we requested krbtgt/<REALM> and got exactly that, it's not a referral
        if enc_part.sname == self.target_server {
            return false;
        }
        // It's a krbtgt for a different realm → referral
        true
    }

    /// Handle a referral TGT response.
    fn handle_referral(
        &mut self,
        rep: &crate::types::KdcRep,
        enc_part: &EncKdcRepPart,
        resume: ResumeState,
    ) -> Result<TgsStepResult, Krb5Error> {
        let (mut realms_seen, referral_count) = match resume {
            ResumeState::Referrals {
                realms_seen,
                referral_count,
            } => (realms_seen, referral_count),
            ResumeState::NonReferral => {
                // Got a referral in non-referral mode — treat as error
                return Err(Krb5Error::ReplyValidation(
                    "unexpected referral in non-referral mode",
                ));
            }
        };

        let new_count = referral_count + 1;
        if new_count > MAX_REFERRAL_HOPS {
            return Err(Krb5Error::ReferralLimitExceeded(MAX_REFERRAL_HOPS));
        }

        // Extract the referral realm from the TGT's sname (krbtgt/REALM)
        let referral_realm =
            String::from_utf8_lossy(enc_part.sname.name_string[1].as_bytes()).to_string();

        // Loop detection
        if realms_seen.contains(&referral_realm) {
            return Err(Krb5Error::ReferralLoop {
                realm: referral_realm,
            });
        }
        realms_seen.push(referral_realm.clone());

        // Build a Credential from the referral TGT.
        //
        // ok-as-delegate propagation (per MIT krb5 behavior):
        // Strip OK_AS_DELEGATE from the referral TGT unless the
        // cross-realm TGT we used to make this request also had it.
        // This prevents a foreign KDC from unilaterally granting
        // delegation rights.
        let mut referral_flags = enc_part.flags;
        if !self.cur_tgt.flags.contains(TicketFlags::OK_AS_DELEGATE) {
            *referral_flags &= !TicketFlags::OK_AS_DELEGATE;
        }

        let referral_tgt = Credential {
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
            flags: referral_flags,
            addresses: enc_part.caddr.clone(),
            authdata: None,
        };

        // Use the referral TGT for the next request
        self.cur_tgt = referral_tgt;

        // Send TGS-REQ to the referral realm
        let tgs_req = self.build_tgs_req(true)?;
        self.state = TgsState::AwaitReply {
            resume: ResumeState::Referrals {
                realms_seen,
                referral_count: new_count,
            },
        };
        self.last_realm = referral_realm.clone();
        Ok(TgsStepResult::SendToKdc {
            data: tgs_req,
            realm: referral_realm,
        })
    }

    /// Build a TGS-REQ message.
    ///
    /// Returns the DER-encoded TGS-REQ. Generates a fresh subkey and nonce.
    fn build_tgs_req(&mut self, canonicalize: bool) -> Result<Vec<u8>, Krb5Error> {
        // Generate random nonce (31-bit, same as AS exchange)
        self.nonce = rand::random::<u32>() & 0x7FFF_FFFF;

        // Generate subkey (same etype as TGT session key)
        let etype = self.cur_tgt.session_key.keytype;
        let profile = find_etype(etype).map_err(|_| Krb5Error::UnsupportedEtype(etype))?;
        let random_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(
            (0..profile.key_bytes())
                .map(|_| rand::random::<u8>())
                .collect(),
        );
        let mut subkey_bytes = profile
            .random_to_key(random_bytes.as_ref())
            .map_err(|e| Krb5Error::Crypto(e.to_string()))?;
        // Move key bytes out of Zeroizing without cloning.
        // std::mem::take replaces the inner Vec with empty (zeroized on Zeroizing drop).
        let subkey = EncryptionKey::new(etype, std::mem::take(&mut *subkey_bytes));
        self.subkey = Some(subkey.clone());

        // Build KDC-REQ-BODY
        let target_realm = self.tgt_target_realm();
        let realm = GeneralString::from_bytes(target_realm.as_bytes())
            .map_err(|_| Krb5Error::ReplyValidation("invalid realm string"))?;

        let mut kdc_opts = KdcOptions::RENEWABLE;
        if self.options.forwardable {
            kdc_opts |= KdcOptions::FORWARDABLE;
        }
        if canonicalize {
            kdc_opts |= KdcOptions::CANONICALIZE;
        }

        // Request 10h lifetime; KDC will cap to its policy maximum
        let till = now_kerberos()
            .checked_add_signed(chrono::Duration::hours(10))
            .ok_or(Krb5Error::ReplyValidation("till overflow"))?;

        let req_body = KdcReqBody {
            kdc_options: KerberosFlags::new(kdc_opts),
            cname: None, // TGS-REQ does not include cname in body
            realm,
            sname: Some(self.target_server.clone()),
            from: None,
            till,
            rtime: None,
            nonce: self.nonce,
            etype: self.options.etypes.clone(),
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        };

        // DER-encode req_body for checksum computation
        let req_body_der = rasn::der::encode(&req_body)?;

        // Build PA-TGS-REQ (AP-REQ wrapping the TGT)
        let pa_tgs_req = self.build_pa_tgs_req(&req_body_der, &subkey)?;

        // Build padata list
        let mut padata = vec![pa_tgs_req];

        // Add PA-PAC-OPTIONS if requested
        if self.options.pac_options {
            padata.push(build_pa_pac_options()?);
        }

        // Build TGS-REQ
        let kdc_req = KdcReq {
            pvno: 5,
            msg_type: 12, // TGS-REQ
            padata: Some(padata),
            req_body,
        };

        let tgs_req = TgsReq(kdc_req);
        let der = rasn::der::encode(&tgs_req)?;
        self.last_req_bytes = der.clone();

        Ok(der)
    }

    /// Build PA-TGS-REQ padata: AP-REQ wrapping the TGT with keyed checksum.
    fn build_pa_tgs_req(
        &self,
        req_body_der: &[u8],
        subkey: &EncryptionKey,
    ) -> Result<PaData, Krb5Error> {
        let session_key = &self.cur_tgt.session_key;
        let etype = session_key.keytype;
        let profile = find_etype(etype).map_err(|_| Krb5Error::UnsupportedEtype(etype))?;

        // 1. Compute keyed checksum of DER-encoded KDC-REQ-BODY (key usage 6)
        let cksum_bytes = profile
            .checksum(
                session_key.key_bytes(),
                key_usage::TGS_REQ_AUTH_CKSUM,
                req_body_der,
            )
            .map_err(|e| Krb5Error::Crypto(e.to_string()))?;

        let cksum = Checksum {
            cksumtype: profile.checksum_type(),
            checksum: cksum_bytes.into(),
        };

        // 2. Build Authenticator
        let now = Utc::now();
        let usec = now.timestamp_subsec_micros() as i32;
        let ctime = now
            .with_nanosecond(0)
            .unwrap_or(now)
            .with_timezone(&UTC_OFFSET);

        let crealm = GeneralString::from_bytes(self.cur_tgt.crealm.as_bytes())
            .map_err(|_| Krb5Error::ReplyValidation("invalid crealm string"))?;

        let authenticator = Authenticator {
            authenticator_vno: 5,
            crealm,
            cname: self.cur_tgt.client.clone(),
            cksum: Some(cksum),
            cusec: usec,
            ctime,
            subkey: Some(subkey.clone()),
            seq_number: None,
            authorization_data: None,
        };

        // 3. Encrypt Authenticator with TGT session key (key usage 7)
        let auth_der = rasn::der::encode(&authenticator)?;
        let encrypted_auth = profile
            .encrypt(session_key.key_bytes(), key_usage::TGS_REQ_AUTH, &auth_der)
            .map_err(|e| Krb5Error::Crypto(e.to_string()))?;

        // 4. Build AP-REQ
        let ap_req = ApReq {
            pvno: 5,
            msg_type: 14,
            ap_options: KerberosFlags::new(ApOptions::empty()),
            ticket: self.cur_tgt.ticket.clone(),
            authenticator: EncryptedData {
                etype,
                kvno: None,
                cipher: encrypted_auth.into(),
            },
        };

        let ap_req_der = rasn::der::encode(&ap_req)?;

        Ok(PaData {
            padata_type: PA_TGS_REQ,
            padata_value: ap_req_der.into(),
        })
    }
}

/// Decode EncTgsRepPart, trying APPLICATION 26 first, then EncKdcRepPart bare.
fn decode_enc_tgs_rep_part(plaintext: &[u8]) -> Result<EncKdcRepPart, Krb5Error> {
    // Try EncTgsRepPart (APPLICATION 26) first
    if let Ok(enc_tgs) = rasn::der::decode::<EncTgsRepPart>(plaintext) {
        return Ok(enc_tgs.0);
    }
    // Some KDCs may send EncKdcRepPart without APPLICATION tag
    rasn::der::decode::<EncKdcRepPart>(plaintext).map_err(Krb5Error::Asn1Decode)
}

/// Build PA-PAC-OPTIONS padata with claims-aware flag.
fn build_pa_pac_options() -> Result<PaData, Krb5Error> {
    use crate::types::PaPacOptions;
    use rasn::types::BitString;

    let pac_options = PaPacOptions {
        flags: BitString::from_slice(&PA_PAC_OPTIONS_FLAGS),
    };
    let der = rasn::der::encode(&pac_options)?;

    Ok(PaData {
        padata_type: PA_PAC_OPTIONS,
        padata_value: der.into(),
    })
}

/// Get current time as KerberosTime (truncated to whole seconds).
fn now_kerberos() -> KerberosTime {
    let now = Utc::now();
    let truncated = now.with_nanosecond(0).unwrap_or(now);
    truncated.with_timezone(&UTC_OFFSET)
}

/// Compute absolute time difference between two KerberosTime values.
fn time_diff(a: &KerberosTime, b: &KerberosTime) -> Duration {
    let chrono_diff = if *a >= *b { *a - *b } else { *b - *a };
    chrono_diff.to_std().unwrap_or(Duration::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        EncKdcRepPart, EncryptedData, EncryptionKey, Flags, KdcRep, KerberosFlags, LastReqEntry,
        PrincipalName, Ticket, TicketFlags,
    };
    use chrono::{TimeZone, Utc};
    use rasn::types::{GeneralString, OctetString};

    fn make_time(secs: i64) -> KerberosTime {
        Utc.timestamp_opt(secs, 0)
            .single()
            .expect("valid")
            .with_timezone(&UTC_OFFSET)
    }

    fn make_realm(s: &str) -> GeneralString {
        GeneralString::from_bytes(s.as_bytes()).expect("valid realm")
    }

    fn make_enc_key(etype: i32, len: usize) -> EncryptionKey {
        EncryptionKey::new(etype, vec![0xABu8; len])
    }

    fn make_tgt(realm: &str) -> Credential {
        Credential {
            client: PrincipalName::new_principal("user"),
            crealm: realm.to_string(),
            server: PrincipalName::new_srv_inst("krbtgt", realm),
            srealm: realm.to_string(),
            session_key: make_enc_key(18, 32),
            times: TicketTimes {
                authtime: make_time(1_700_000_000),
                starttime: Some(make_time(1_700_000_000)),
                endtime: make_time(1_700_036_000),
                renew_till: None,
            },
            ticket: Ticket {
                tkt_vno: 5,
                realm: make_realm(realm),
                sname: PrincipalName::new_srv_inst("krbtgt", realm),
                enc_part: EncryptedData {
                    etype: 18,
                    kvno: Some(1),
                    cipher: OctetString::from(vec![0u8; 64]),
                },
            },
            flags: KerberosFlags::new(
                TicketFlags::FORWARDABLE | TicketFlags::RENEWABLE | TicketFlags::INITIAL,
            ),
            addresses: None,
            authdata: None,
        }
    }

    #[test]
    fn test_tgs_options_default() {
        let opts = TgsOptions::default();
        assert!(opts.canonicalize);
        assert!(opts.forwardable);
        assert_eq!(opts.etypes, vec![18, 17]);
        assert!(opts.pac_options);
    }

    #[test]
    fn test_new_exchange_initial_step_produces_tgs_req() {
        let tgt = make_tgt("EXAMPLE.COM");
        let target = PrincipalName::new_srv_inst("HTTP", "web.example.com");
        let mut exchange = TgsExchange::new(tgt, target, TgsOptions::default());

        let result = exchange.step(&[]).expect("initial step should succeed");
        match result {
            TgsStepResult::SendToKdc { data, realm } => {
                assert_eq!(realm, "EXAMPLE.COM");
                // Should decode as TGS-REQ
                let tgs_req: TgsReq = rasn::der::decode(&data).expect("should decode as TGS-REQ");
                assert_eq!(tgs_req.0.pvno, 5);
                assert_eq!(tgs_req.0.msg_type, 12);
                // Should have PA-TGS-REQ padata
                let padata = tgs_req.0.padata.expect("should have padata");
                assert!(padata.iter().any(|pa| pa.padata_type == PA_TGS_REQ));
                // Nonce should be set
                assert_ne!(tgs_req.0.req_body.nonce, 0);
                // sname should be the target service
                let sname = tgs_req.0.req_body.sname.expect("should have sname");
                assert_eq!(sname.name_string.len(), 2);
                assert_eq!(sname.name_string[0].as_bytes(), b"HTTP");
                assert_eq!(sname.name_string[1].as_bytes(), b"web.example.com");
                // cname should be absent (per TGS-REQ spec)
                assert!(tgs_req.0.req_body.cname.is_none());
                // KDC options should include CANONICALIZE
                let opts_bytes = tgs_req.0.req_body.kdc_options.to_bytes();
                let opts_u32 = u32::from_be_bytes(opts_bytes);
                assert_ne!(opts_u32 & KdcOptions::CANONICALIZE.bits(), 0);
            }
            _ => panic!("expected SendToKdc on first step"),
        }

        // Subkey should be generated
        assert!(exchange.subkey.is_some());
    }

    #[test]
    fn test_exchange_empty_reply_rejected() {
        let tgt = make_tgt("EXAMPLE.COM");
        let target = PrincipalName::new_srv_inst("HTTP", "web.example.com");
        let mut exchange = TgsExchange::new(tgt, target, TgsOptions::default());
        let _ = exchange.step(&[]).expect("initial step");

        let result = exchange.step(&[]);
        assert!(matches!(result, Err(Krb5Error::ReplyValidation(_))));
    }

    #[test]
    fn test_exchange_response_too_big_returns_retry() {
        let tgt = make_tgt("EXAMPLE.COM");
        let target = PrincipalName::new_srv_inst("HTTP", "web.example.com");
        let mut exchange = TgsExchange::new(tgt, target, TgsOptions::default());
        let initial = exchange.step(&[]).expect("initial step");

        let original_data = match &initial {
            TgsStepResult::SendToKdc { data, .. } => data.clone(),
            _ => panic!("expected SendToKdc"),
        };

        let error_reply = build_krb_error(KRB_ERR_RESPONSE_TOO_BIG, "EXAMPLE.COM");
        let result = exchange.step(&error_reply).expect("should return RetryTcp");
        match result {
            TgsStepResult::RetryTcp { data, realm } => {
                assert_eq!(realm, "EXAMPLE.COM");
                assert_eq!(data, original_data);
            }
            other => panic!("expected RetryTcp, got: {other:?}"),
        }
    }

    #[test]
    fn test_exchange_s_principal_unknown_falls_back_to_non_referral() {
        let tgt = make_tgt("EXAMPLE.COM");
        let target = PrincipalName::new_srv_inst("HTTP", "web.example.com");
        let mut exchange = TgsExchange::new(tgt, target, TgsOptions::default());
        let _ = exchange.step(&[]).expect("initial step");

        let error_reply = build_krb_error(KDC_ERR_S_PRINCIPAL_UNKNOWN, "EXAMPLE.COM");
        let result = exchange
            .step(&error_reply)
            .expect("should fallback to non-referral");
        match result {
            TgsStepResult::SendToKdc { data, realm } => {
                assert_eq!(realm, "EXAMPLE.COM");
                // The new TGS-REQ should NOT have CANONICALIZE flag
                let tgs_req: TgsReq = rasn::der::decode(&data).expect("decode TGS-REQ");
                let opts_bytes = tgs_req.0.req_body.kdc_options.to_bytes();
                let opts_u32 = u32::from_be_bytes(opts_bytes);
                assert_eq!(opts_u32 & KdcOptions::CANONICALIZE.bits(), 0);
            }
            _ => panic!("expected SendToKdc"),
        }
    }

    #[test]
    fn test_exchange_s_principal_unknown_no_double_fallback() {
        let tgt = make_tgt("EXAMPLE.COM");
        let target = PrincipalName::new_srv_inst("HTTP", "web.example.com");
        let mut exchange = TgsExchange::new(tgt, target, TgsOptions::default());
        let _ = exchange.step(&[]).expect("initial step");

        // First S_PRINCIPAL_UNKNOWN → falls back
        let error_reply = build_krb_error(KDC_ERR_S_PRINCIPAL_UNKNOWN, "EXAMPLE.COM");
        let _ = exchange.step(&error_reply).expect("fallback");

        // Second S_PRINCIPAL_UNKNOWN → should propagate as error
        let result = exchange.step(&error_reply);
        assert!(matches!(result, Err(Krb5Error::KdcError(_))));
    }

    #[test]
    fn test_exchange_kdc_error_propagated() {
        let tgt = make_tgt("EXAMPLE.COM");
        let target = PrincipalName::new_srv_inst("HTTP", "web.example.com");
        let mut exchange = TgsExchange::new(tgt, target, TgsOptions::default());
        let _ = exchange.step(&[]).expect("initial step");

        // Generic error should propagate
        let error_reply = build_krb_error(60, "EXAMPLE.COM"); // Generic
        let result = exchange.step(&error_reply);
        match result {
            Err(Krb5Error::KdcError(err)) => {
                assert_eq!(err.error_code, 60);
            }
            other => panic!("expected KdcError, got: {other:?}"),
        }
    }

    #[test]
    fn test_non_canonicalize_mode() {
        let tgt = make_tgt("EXAMPLE.COM");
        let target = PrincipalName::new_srv_inst("HTTP", "web.example.com");
        let opts = TgsOptions {
            canonicalize: false,
            ..TgsOptions::default()
        };
        let mut exchange = TgsExchange::new(tgt, target, opts);

        let result = exchange.step(&[]).expect("initial step");
        match result {
            TgsStepResult::SendToKdc { data, .. } => {
                let tgs_req: TgsReq = rasn::der::decode(&data).expect("decode TGS-REQ");
                let opts_bytes = tgs_req.0.req_body.kdc_options.to_bytes();
                let opts_u32 = u32::from_be_bytes(opts_bytes);
                // CANONICALIZE should NOT be set
                assert_eq!(opts_u32 & KdcOptions::CANONICALIZE.bits(), 0);
            }
            _ => panic!("expected SendToKdc"),
        }
    }

    #[test]
    fn test_validate_nonce_mismatch() {
        let tgt = make_tgt("EXAMPLE.COM");
        let target = PrincipalName::new_srv_inst("HTTP", "web.example.com");
        let exchange = TgsExchange::new(tgt, target, TgsOptions::default());

        let now = make_time(1_700_000_000);
        let enc_part = EncKdcRepPart {
            key: make_enc_key(18, 32),
            last_req: vec![LastReqEntry {
                lr_type: 0,
                lr_value: now,
            }],
            nonce: 99999, // wrong nonce
            key_expiration: None,
            flags: KerberosFlags::new(TicketFlags::FORWARDABLE),
            authtime: now,
            starttime: Some(now),
            endtime: make_time(1_700_036_000),
            renew_till: None,
            srealm: make_realm("EXAMPLE.COM"),
            sname: PrincipalName::new_srv_inst("HTTP", "web.example.com"),
            caddr: None,
            encrypted_pa_data: None,
        };

        let rep = KdcRep {
            pvno: 5,
            msg_type: 13,
            padata: None,
            crealm: make_realm("EXAMPLE.COM"),
            cname: PrincipalName::new_principal("user"),
            ticket: Ticket {
                tkt_vno: 5,
                realm: make_realm("EXAMPLE.COM"),
                sname: PrincipalName::new_srv_inst("HTTP", "web.example.com"),
                enc_part: EncryptedData {
                    etype: 18,
                    kvno: Some(1),
                    cipher: OctetString::from(vec![0u8; 32]),
                },
            },
            enc_part: EncryptedData {
                etype: 18,
                kvno: None,
                cipher: OctetString::from(vec![0u8; 32]),
            },
        };

        let result = exchange.validate_tgs_reply(&rep, &enc_part);
        assert!(matches!(
            result,
            Err(Krb5Error::ReplyValidation("nonce mismatch"))
        ));
    }

    #[test]
    fn test_is_referral_tgt() {
        let tgt = make_tgt("EXAMPLE.COM");
        let target = PrincipalName::new_srv_inst("HTTP", "web.example.com");
        let exchange = TgsExchange::new(tgt, target, TgsOptions::default());

        let now = make_time(1_700_000_000);

        // Referral TGT (krbtgt/OTHER.COM)
        let referral_enc = EncKdcRepPart {
            key: make_enc_key(18, 32),
            last_req: vec![],
            nonce: 0,
            key_expiration: None,
            flags: KerberosFlags::new(TicketFlags::FORWARDABLE),
            authtime: now,
            starttime: None,
            endtime: make_time(1_700_036_000),
            renew_till: None,
            srealm: make_realm("EXAMPLE.COM"),
            sname: PrincipalName::new_srv_inst("krbtgt", "OTHER.COM"),
            caddr: None,
            encrypted_pa_data: None,
        };
        assert!(exchange.is_referral_tgt(&referral_enc));

        // Service ticket (HTTP/web.example.com)
        let service_enc = EncKdcRepPart {
            sname: PrincipalName::new_srv_inst("HTTP", "web.example.com"),
            ..referral_enc
        };
        assert!(!exchange.is_referral_tgt(&service_enc));
    }

    #[test]
    fn test_referral_loop_detection() {
        let tgt = make_tgt("EXAMPLE.COM");
        let target = PrincipalName::new_srv_inst("HTTP", "web.other.com");
        let mut exchange = TgsExchange::new(tgt, target, TgsOptions::default());

        let now = make_time(1_700_000_000);
        let rep = KdcRep {
            pvno: 5,
            msg_type: 13,
            padata: None,
            crealm: make_realm("EXAMPLE.COM"),
            cname: PrincipalName::new_principal("user"),
            ticket: Ticket {
                tkt_vno: 5,
                realm: make_realm("EXAMPLE.COM"),
                sname: PrincipalName::new_srv_inst("krbtgt", "EXAMPLE.COM"),
                enc_part: EncryptedData {
                    etype: 18,
                    kvno: Some(1),
                    cipher: OctetString::from(vec![0u8; 64]),
                },
            },
            enc_part: EncryptedData {
                etype: 18,
                kvno: None,
                cipher: OctetString::from(vec![0u8; 64]),
            },
        };

        let enc_part = EncKdcRepPart {
            key: make_enc_key(18, 32),
            last_req: vec![],
            nonce: 0,
            key_expiration: None,
            flags: KerberosFlags::new(TicketFlags::FORWARDABLE),
            authtime: now,
            starttime: None,
            endtime: make_time(1_700_036_000),
            renew_till: None,
            srealm: make_realm("EXAMPLE.COM"),
            sname: PrincipalName::new_srv_inst("krbtgt", "EXAMPLE.COM"),
            caddr: None,
            encrypted_pa_data: None,
        };

        // Simulate referral back to EXAMPLE.COM (already seen)
        let resume = ResumeState::Referrals {
            realms_seen: vec!["EXAMPLE.COM".to_string()],
            referral_count: 1,
        };

        let result = exchange.handle_referral(&rep, &enc_part, resume);
        assert!(matches!(result, Err(Krb5Error::ReferralLoop { .. })));
    }

    #[test]
    fn test_referral_limit_exceeded() {
        let tgt = make_tgt("EXAMPLE.COM");
        let target = PrincipalName::new_srv_inst("HTTP", "web.example.com");
        let mut exchange = TgsExchange::new(tgt, target, TgsOptions::default());

        let now = make_time(1_700_000_000);
        let rep = KdcRep {
            pvno: 5,
            msg_type: 13,
            padata: None,
            crealm: make_realm("EXAMPLE.COM"),
            cname: PrincipalName::new_principal("user"),
            ticket: Ticket {
                tkt_vno: 5,
                realm: make_realm("EXAMPLE.COM"),
                sname: PrincipalName::new_srv_inst("krbtgt", "REALM-11"),
                enc_part: EncryptedData {
                    etype: 18,
                    kvno: Some(1),
                    cipher: OctetString::from(vec![0u8; 64]),
                },
            },
            enc_part: EncryptedData {
                etype: 18,
                kvno: None,
                cipher: OctetString::from(vec![0u8; 64]),
            },
        };

        let enc_part = EncKdcRepPart {
            key: make_enc_key(18, 32),
            last_req: vec![],
            nonce: 0,
            key_expiration: None,
            flags: KerberosFlags::new(TicketFlags::FORWARDABLE),
            authtime: now,
            starttime: None,
            endtime: make_time(1_700_036_000),
            renew_till: None,
            srealm: make_realm("EXAMPLE.COM"),
            sname: PrincipalName::new_srv_inst("krbtgt", "REALM-11"),
            caddr: None,
            encrypted_pa_data: None,
        };

        let resume = ResumeState::Referrals {
            realms_seen: (0..10).map(|i| format!("REALM-{i}")).collect(),
            referral_count: MAX_REFERRAL_HOPS,
        };

        let result = exchange.handle_referral(&rep, &enc_part, resume);
        assert!(matches!(
            result,
            Err(Krb5Error::ReferralLimitExceeded(MAX_REFERRAL_HOPS))
        ));
    }

    #[test]
    fn test_ok_as_delegate_stripped_when_cross_realm_tgt_lacks_it() {
        // When cur_tgt does NOT have OK_AS_DELEGATE, the referral TGT's
        // OK_AS_DELEGATE should be stripped.
        let tgt = make_tgt("EXAMPLE.COM");
        // Verify our test TGT does NOT have OK_AS_DELEGATE
        assert!(!tgt.flags.contains(TicketFlags::OK_AS_DELEGATE));

        let target = PrincipalName::new_srv_inst("HTTP", "web.other.com");
        let mut exchange = TgsExchange::new(tgt, target, TgsOptions::default());

        let now = make_time(1_700_000_000);
        let rep = KdcRep {
            pvno: 5,
            msg_type: 13,
            padata: None,
            crealm: make_realm("EXAMPLE.COM"),
            cname: PrincipalName::new_principal("user"),
            ticket: Ticket {
                tkt_vno: 5,
                realm: make_realm("EXAMPLE.COM"),
                sname: PrincipalName::new_srv_inst("krbtgt", "OTHER.COM"),
                enc_part: EncryptedData {
                    etype: 18,
                    kvno: Some(1),
                    cipher: OctetString::from(vec![0u8; 64]),
                },
            },
            enc_part: EncryptedData {
                etype: 18,
                kvno: None,
                cipher: OctetString::from(vec![0u8; 64]),
            },
        };

        // Referral TGT has OK_AS_DELEGATE set by the foreign KDC
        let enc_part = EncKdcRepPart {
            key: make_enc_key(18, 32),
            last_req: vec![],
            nonce: 0,
            key_expiration: None,
            flags: KerberosFlags::new(TicketFlags::FORWARDABLE | TicketFlags::OK_AS_DELEGATE),
            authtime: now,
            starttime: None,
            endtime: make_time(1_700_036_000),
            renew_till: None,
            srealm: make_realm("EXAMPLE.COM"),
            sname: PrincipalName::new_srv_inst("krbtgt", "OTHER.COM"),
            caddr: None,
            encrypted_pa_data: None,
        };

        let resume = ResumeState::Referrals {
            realms_seen: vec!["EXAMPLE.COM".to_string()],
            referral_count: 0,
        };

        // handle_referral should strip OK_AS_DELEGATE from cur_tgt
        let _result = exchange.handle_referral(&rep, &enc_part, resume);
        // After referral handling, cur_tgt should NOT have OK_AS_DELEGATE
        assert!(
            !exchange.cur_tgt.flags.contains(TicketFlags::OK_AS_DELEGATE),
            "OK_AS_DELEGATE should be stripped from referral TGT when cross-realm TGT lacks it"
        );
    }

    #[test]
    fn test_ok_as_delegate_preserved_when_cross_realm_tgt_has_it() {
        // When cur_tgt HAS OK_AS_DELEGATE, the referral TGT should keep it.
        let mut tgt = make_tgt("EXAMPLE.COM");
        *tgt.flags |= TicketFlags::OK_AS_DELEGATE;

        let target = PrincipalName::new_srv_inst("HTTP", "web.other.com");
        let mut exchange = TgsExchange::new(tgt, target, TgsOptions::default());

        let now = make_time(1_700_000_000);
        let rep = KdcRep {
            pvno: 5,
            msg_type: 13,
            padata: None,
            crealm: make_realm("EXAMPLE.COM"),
            cname: PrincipalName::new_principal("user"),
            ticket: Ticket {
                tkt_vno: 5,
                realm: make_realm("EXAMPLE.COM"),
                sname: PrincipalName::new_srv_inst("krbtgt", "OTHER.COM"),
                enc_part: EncryptedData {
                    etype: 18,
                    kvno: Some(1),
                    cipher: OctetString::from(vec![0u8; 64]),
                },
            },
            enc_part: EncryptedData {
                etype: 18,
                kvno: None,
                cipher: OctetString::from(vec![0u8; 64]),
            },
        };

        let enc_part = EncKdcRepPart {
            key: make_enc_key(18, 32),
            last_req: vec![],
            nonce: 0,
            key_expiration: None,
            flags: KerberosFlags::new(TicketFlags::FORWARDABLE | TicketFlags::OK_AS_DELEGATE),
            authtime: now,
            starttime: None,
            endtime: make_time(1_700_036_000),
            renew_till: None,
            srealm: make_realm("EXAMPLE.COM"),
            sname: PrincipalName::new_srv_inst("krbtgt", "OTHER.COM"),
            caddr: None,
            encrypted_pa_data: None,
        };

        let resume = ResumeState::Referrals {
            realms_seen: vec!["EXAMPLE.COM".to_string()],
            referral_count: 0,
        };

        let _result = exchange.handle_referral(&rep, &enc_part, resume);
        assert!(
            exchange.cur_tgt.flags.contains(TicketFlags::OK_AS_DELEGATE),
            "OK_AS_DELEGATE should be preserved when cross-realm TGT also has it"
        );
    }

    /// Helper: build a DER-encoded KRB-ERROR.
    fn build_krb_error(error_code: i32, realm: &str) -> Vec<u8> {
        let now = now_kerberos();
        let krb_error = KrbErrorMsg {
            pvno: 5,
            msg_type: 30,
            ctime: None,
            cusec: None,
            stime: now,
            susec: 0,
            error_code,
            crealm: None,
            cname: None,
            realm: make_realm(realm),
            sname: PrincipalName::new_srv_inst("krbtgt", realm),
            e_text: None,
            e_data: None,
        };
        rasn::der::encode(&krb_error).expect("encode KRB-ERROR")
    }
}
