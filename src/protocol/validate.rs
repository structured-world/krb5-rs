//! AS-REP validation (following MIT's `verify_as_reply()`).

use std::time::Duration;

use crate::types::{EncKdcRepPart, KdcRep, KdcReqBody, KerberosTime};
use crate::Krb5Error;

/// Maximum allowed clock skew between client and KDC (default 5 minutes).
pub(crate) const DEFAULT_MAX_CLOCK_SKEW: Duration = Duration::from_secs(300);

/// Validate an AS-REP response against the original request.
///
/// Follows MIT krb5's `verify_as_reply()` checks:
/// 1. Nonce match
/// 2. Server principal match (always validated)
/// 3. Client principal match (unless canonicalize)
/// 4. Realm checks (request realm vs reply crealm, ticket realm vs enc-part srealm)
/// 5. Ticket sname matches enc-part sname
/// 6. Clock skew check on starttime/authtime
pub(crate) fn validate_as_reply(
    nonce: u32,
    request_body: &KdcReqBody,
    reply: &KdcRep,
    enc_part: &EncKdcRepPart,
    canonicalize: bool,
    max_clock_skew: Duration,
    now: KerberosTime,
) -> Result<(), Krb5Error> {
    // 1. Nonce must match
    if enc_part.nonce != nonce {
        return Err(Krb5Error::ReplyValidation("nonce mismatch"));
    }

    // 2. Server principal must always match (regardless of canonicalize)
    if let Some(ref requested_sname) = request_body.sname {
        if enc_part.sname != *requested_sname {
            return Err(Krb5Error::ReplyValidation("server principal mismatch"));
        }
    }

    // 3. Client principal must match (unless canonicalize was requested)
    if !canonicalize {
        if let Some(ref requested_cname) = request_body.cname {
            if reply.cname != *requested_cname {
                return Err(Krb5Error::ReplyValidation("client principal mismatch"));
            }
        }
    }

    // 4. Realm checks: request realm must match reply crealm,
    //    and ticket realm must match enc-part srealm
    if request_body.realm != reply.crealm {
        return Err(Krb5Error::ReplyValidation("realm mismatch"));
    }
    if reply.ticket.realm != enc_part.srealm {
        return Err(Krb5Error::ReplyValidation("ticket/enc-part realm mismatch"));
    }

    // 5. Ticket server must match enc-part server
    if reply.ticket.sname != enc_part.sname {
        return Err(Krb5Error::ReplyValidation(
            "ticket/enc-part server mismatch",
        ));
    }

    // 6. Start time within acceptable clock skew
    let starttime = enc_part.starttime.as_ref().unwrap_or(&enc_part.authtime);
    let skew = time_diff(starttime, &now);
    if skew > max_clock_skew {
        return Err(Krb5Error::ClockSkew {
            max_skew: max_clock_skew,
        });
    }

    Ok(())
}

/// Compute absolute time difference between two KerberosTime values.
fn time_diff(a: &KerberosTime, b: &KerberosTime) -> Duration {
    // KerberosTime = chrono::DateTime<FixedOffset>
    let diff = (*a - *b).abs();
    diff.to_std().unwrap_or(Duration::ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        EncKdcRepPart, EncryptedData, EncryptionKey, KdcOptions, KdcRep, KdcReqBody, KerberosFlags,
        LastReqEntry, PrincipalName, Ticket, TicketFlags,
    };
    use chrono::{FixedOffset, TimeZone, Utc};
    use rasn::types::{GeneralString, OctetString};

    fn make_time(secs_from_epoch: i64) -> KerberosTime {
        Utc.timestamp_opt(secs_from_epoch, 0)
            .single()
            .expect("valid timestamp")
            .with_timezone(&FixedOffset::east_opt(0).expect("UTC"))
    }

    fn make_realm(s: &str) -> GeneralString {
        GeneralString::from_bytes(s.as_bytes()).expect("valid realm")
    }

    fn make_principal(name: &str) -> PrincipalName {
        PrincipalName::new_principal(name)
    }

    fn make_srv_inst(svc: &str, inst: &str) -> PrincipalName {
        PrincipalName::new_srv_inst(svc, inst)
    }

    fn make_ticket(sname: PrincipalName, realm: &str) -> Ticket {
        Ticket {
            tkt_vno: 5,
            realm: make_realm(realm),
            sname,
            enc_part: EncryptedData {
                etype: 18,
                kvno: Some(1),
                cipher: OctetString::from(vec![0u8; 32]),
            },
        }
    }

    fn make_enc_key() -> EncryptionKey {
        EncryptionKey::new(18, vec![0u8; 32])
    }

    /// Build a consistent request body, reply, and enc_part for validation tests.
    fn make_valid_set(nonce: u32, now: KerberosTime) -> (KdcReqBody, KdcRep, EncKdcRepPart) {
        let client = make_principal("user");
        let server = make_srv_inst("krbtgt", "EXAMPLE.COM");
        let realm = make_realm("EXAMPLE.COM");

        let req_body = KdcReqBody {
            kdc_options: KerberosFlags::new(
                KdcOptions::FORWARDABLE | KdcOptions::RENEWABLE | KdcOptions::CANONICALIZE,
            ),
            cname: Some(client.clone()),
            realm: realm.clone(),
            sname: Some(server.clone()),
            from: None,
            till: make_time(1_800_000_000),
            rtime: None,
            nonce,
            etype: vec![18, 17],
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        };

        let enc_part = EncKdcRepPart {
            key: make_enc_key(),
            last_req: vec![LastReqEntry {
                lr_type: 0,
                lr_value: now,
            }],
            nonce,
            key_expiration: None,
            flags: KerberosFlags::new(TicketFlags::FORWARDABLE | TicketFlags::RENEWABLE),
            authtime: now,
            starttime: Some(now),
            endtime: make_time(1_800_000_000),
            renew_till: None,
            srealm: realm.clone(),
            sname: server.clone(),
            caddr: None,
            encrypted_pa_data: None,
        };

        let reply = KdcRep {
            pvno: 5,
            msg_type: 11,
            padata: None,
            crealm: realm.clone(),
            cname: client.clone(),
            ticket: make_ticket(server.clone(), "EXAMPLE.COM"),
            enc_part: EncryptedData {
                etype: 18,
                kvno: None,
                cipher: OctetString::from(vec![0u8; 32]),
            },
        };

        (req_body, reply, enc_part)
    }

    #[test]
    fn test_valid_reply_passes() {
        let now = make_time(1_700_000_000);
        let (req_body, reply, enc_part) = make_valid_set(12345, now);
        let result = validate_as_reply(
            12345,
            &req_body,
            &reply,
            &enc_part,
            true, // canonicalize
            DEFAULT_MAX_CLOCK_SKEW,
            now,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_nonce_mismatch_rejected() {
        let now = make_time(1_700_000_000);
        let (req_body, reply, enc_part) = make_valid_set(12345, now);
        let result = validate_as_reply(
            99999, // wrong nonce
            &req_body,
            &reply,
            &enc_part,
            true,
            DEFAULT_MAX_CLOCK_SKEW,
            now,
        );
        assert!(matches!(
            result,
            Err(Krb5Error::ReplyValidation("nonce mismatch"))
        ));
    }

    #[test]
    fn test_server_principal_mismatch_without_canonicalize() {
        let now = make_time(1_700_000_000);
        let (req_body, reply, mut enc_part) = make_valid_set(12345, now);
        // Tamper: change enc_part sname
        enc_part.sname = make_srv_inst("krbtgt", "OTHER.COM");
        // Also update ticket to match enc_part (so check 4 passes)
        let mut reply = reply;
        reply.ticket.sname = enc_part.sname.clone();

        let result = validate_as_reply(
            12345,
            &req_body,
            &reply,
            &enc_part,
            false, // no canonicalize — should check principals
            DEFAULT_MAX_CLOCK_SKEW,
            now,
        );
        assert!(matches!(
            result,
            Err(Krb5Error::ReplyValidation("server principal mismatch"))
        ));
    }

    #[test]
    fn test_client_principal_mismatch_without_canonicalize() {
        let now = make_time(1_700_000_000);
        let (req_body, mut reply, enc_part) = make_valid_set(12345, now);
        // Tamper: change reply cname
        reply.cname = make_principal("evil");

        let result = validate_as_reply(
            12345,
            &req_body,
            &reply,
            &enc_part,
            false,
            DEFAULT_MAX_CLOCK_SKEW,
            now,
        );
        assert!(matches!(
            result,
            Err(Krb5Error::ReplyValidation("client principal mismatch"))
        ));
    }

    #[test]
    fn test_ticket_server_mismatch() {
        let now = make_time(1_700_000_000);
        let (req_body, mut reply, enc_part) = make_valid_set(12345, now);
        // Tamper: ticket sname differs from enc_part sname
        reply.ticket.sname = make_srv_inst("krbtgt", "DIFFERENT.COM");

        let result = validate_as_reply(
            12345,
            &req_body,
            &reply,
            &enc_part,
            true,
            DEFAULT_MAX_CLOCK_SKEW,
            now,
        );
        assert!(matches!(
            result,
            Err(Krb5Error::ReplyValidation(
                "ticket/enc-part server mismatch"
            ))
        ));
    }

    #[test]
    fn test_clock_skew_rejected() {
        let now = make_time(1_700_000_000);
        // Make enc_part with starttime 10 minutes in the future
        let future = make_time(1_700_000_600);
        let (req_body, reply, mut enc_part) = make_valid_set(12345, future);
        enc_part.starttime = Some(future);

        let result = validate_as_reply(
            12345,
            &req_body,
            &reply,
            &enc_part,
            true,
            DEFAULT_MAX_CLOCK_SKEW, // 5 min
            now,                    // 10 min behind
        );
        assert!(matches!(result, Err(Krb5Error::ClockSkew { .. })));
    }

    #[test]
    fn test_clock_skew_within_tolerance() {
        let now = make_time(1_700_000_000);
        // 4 minutes off — within 5-minute tolerance
        let slightly_off = make_time(1_700_000_240);
        let (req_body, reply, mut enc_part) = make_valid_set(12345, now);
        enc_part.starttime = Some(slightly_off);
        enc_part.authtime = slightly_off;

        let result = validate_as_reply(
            12345,
            &req_body,
            &reply,
            &enc_part,
            true,
            DEFAULT_MAX_CLOCK_SKEW,
            now,
        );
        assert!(result.is_ok());
    }
}
