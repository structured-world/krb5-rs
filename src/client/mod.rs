//! High-level Kerberos client API.
//!
//! Wraps the step-based AS and TGS exchange state machines with async
//! transport, providing a simple interface for acquiring tickets.
//!
//! # Example
//!
//! ```rust,no_run
//! use krb5_rs::client::KerberosClient;
//! use krb5_rs::transport::TcpTransport;
//!
//! # async fn example() -> Result<(), krb5_rs::Krb5Error> {
//! let addr = "192.168.1.100:88".parse().unwrap();
//! let transport = TcpTransport::new(addr);
//! let client = KerberosClient::new("EXAMPLE.COM", transport);
//!
//! let tgt = client.acquire_tgt("user", "password").await?;
//! let ticket = client.get_service_ticket(&tgt, "HTTP/web.example.com").await?;
//! # Ok(())
//! # }
//! ```

use crate::protocol::{
    AsExchange, AsExchangeConfig, Credential, StepResult, TgsExchange, TgsOptions, TgsStepResult,
};
use crate::transport::KdcTransport;
use crate::types::PrincipalName;
use crate::Krb5Error;

/// Maximum number of state machine steps before aborting.
/// Prevents runaway loops in case of protocol bugs.
const MAX_EXCHANGE_STEPS: u32 = 32;

/// High-level Kerberos client bound to a specific realm.
///
/// The client drives protocol state machines over the provided transport,
/// handling the step loop internally.
///
/// Use [`crate::transport::TcpTransport`] or [`crate::transport::UdpTcpTransport`]
/// for general use. The AS/TGS state machines can request an explicit TCP
/// retry after a `KRB_ERR_RESPONSE_TOO_BIG` reply; `KerberosClient` cannot force
/// a transport-specific protocol switch through the generic [`KdcTransport`]
/// interface, so single-protocol UDP transports surface that retry request as
/// an error. [`crate::transport::UdpTcpTransport`] performs the UDP-to-TCP retry
/// internally before the state machine sees the response.
pub struct KerberosClient<T: KdcTransport> {
    /// Kerberos realm.
    realm: String,
    /// Transport for communicating with the KDC.
    transport: T,
}

impl<T: KdcTransport> KerberosClient<T> {
    /// Create a new client for the given realm and transport.
    ///
    /// Prefer TCP-capable transports. A plain UDP transport cannot satisfy an
    /// AS/TGS state-machine TCP retry request because the generic transport
    /// interface intentionally does not expose protocol switching.
    pub fn new(realm: impl Into<String>, transport: T) -> Self {
        Self {
            realm: realm.into(),
            transport,
        }
    }

    /// Get the realm this client is configured for.
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// Obtain a TGT using password authentication.
    ///
    /// Drives the full AS exchange: initial request, pre-authentication
    /// handling, and reply validation.
    pub async fn acquire_tgt(
        &self,
        principal: &str,
        password: &str,
    ) -> Result<Credential, Krb5Error> {
        // Parse via FromStr to get a Result instead of panicking on invalid input.
        // FromStr uses NT_SRV_HST for "svc/host" forms, but for simple names like
        // "user" it produces NT_PRINCIPAL — which is what we need here.
        let client: PrincipalName = principal
            .parse()
            .map_err(|_| Krb5Error::ReplyValidation("invalid client principal name"))?;
        let config = AsExchangeConfig::new(client, &self.realm);
        self.acquire_tgt_with_config(config, password).await
    }

    /// Obtain a TGT using a custom configuration.
    ///
    /// Use this for non-default options (e.g., `request_pac: false`,
    /// custom etypes, custom KDC options).
    pub async fn acquire_tgt_with_config(
        &self,
        config: AsExchangeConfig,
        password: &str,
    ) -> Result<Credential, Krb5Error> {
        let mut exchange = AsExchange::new(config, password);
        let mut kdc_reply = Vec::new();

        for _ in 0..MAX_EXCHANGE_STEPS {
            match exchange.step(&kdc_reply)? {
                StepResult::SendToKdc { data, realm } => {
                    kdc_reply = self.transport.send_recv(&realm, &data).await?;
                }
                StepResult::RetryTcp { .. } => {
                    // The state machine requested a retry over TCP
                    // (typically after a RESPONSE_TOO_BIG over UDP),
                    // but this client cannot explicitly force TCP on the
                    // underlying generic transport. Retrying via the same API
                    // can repeat UDP sends for UdpTransport; UdpTcpTransport
                    // performs the TCP fallback before this point.
                    return Err(Krb5Error::ReplyValidation(
                        "KDC requested TCP retry, but the client transport \
                         cannot explicitly force TCP; configure a TCP-capable \
                         transport such as TcpTransport or UdpTcpTransport",
                    ));
                }
                StepResult::Complete => {
                    return exchange.credential().cloned();
                }
            }
        }

        Err(Krb5Error::ReplyValidation(
            "AS exchange did not complete within step limit",
        ))
    }

    /// Obtain a service ticket using an existing TGT.
    ///
    /// Handles cross-realm referrals transparently. The `service` parameter
    /// should be in the form `SERVICE/hostname` (e.g., `HTTP/web.example.com`).
    pub async fn get_service_ticket(
        &self,
        tgt: &Credential,
        service: &str,
    ) -> Result<Credential, Krb5Error> {
        self.get_service_ticket_with_options(tgt, service, TgsOptions::default())
            .await
    }

    /// Obtain a service ticket with custom TGS options.
    pub async fn get_service_ticket_with_options(
        &self,
        tgt: &Credential,
        service: &str,
        options: TgsOptions,
    ) -> Result<Credential, Krb5Error> {
        let target = parse_service_principal(service)?;
        let mut exchange = TgsExchange::new(tgt.clone(), target, options);
        let mut kdc_reply = Vec::new();

        for _ in 0..MAX_EXCHANGE_STEPS {
            match exchange.step(&kdc_reply)? {
                TgsStepResult::SendToKdc { data, realm } => {
                    kdc_reply = self.transport.send_recv(&realm, &data).await?;
                }
                TgsStepResult::RetryTcp { .. } => {
                    return Err(Krb5Error::ReplyValidation(
                        "TGS exchange requested TCP retry, but the client transport cannot \
                         explicitly force TCP; configure TcpTransport or UdpTcpTransport",
                    ));
                }
                TgsStepResult::Complete => {
                    return exchange.credential().cloned();
                }
            }
        }

        Err(Krb5Error::ReplyValidation(
            "TGS exchange did not complete within step limit",
        ))
    }
}

/// Parse a service principal string into a `PrincipalName`.
///
/// Accepts formats:
/// - `SERVICE/hostname` — e.g., `HTTP/web.example.com`
/// - `SERVICE/hostname@REALM` — realm suffix is stripped (realm comes from TGT)
/// - `krbtgt/REALM` — cross-realm TGT
fn parse_service_principal(service: &str) -> Result<PrincipalName, Krb5Error> {
    // Strip @REALM suffix if present — the realm for the TGS-REQ comes from
    // the TGT, not from the SPN string.
    let without_realm = service.split_once('@').map_or(service, |(left, _)| left);
    match without_realm.split_once('/') {
        Some((svc, host)) => Ok(PrincipalName::new_srv_inst(svc, host)),
        None => Err(Krb5Error::ReplyValidation(
            "service principal must be in SERVICE/hostname format",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_service_principal_valid() {
        let p = parse_service_principal("HTTP/web.example.com").expect("should parse");
        assert_eq!(p.to_string(), "HTTP/web.example.com");
    }

    #[test]
    fn test_parse_service_principal_krbtgt() {
        let p = parse_service_principal("krbtgt/EXAMPLE.COM").expect("should parse");
        assert_eq!(p.to_string(), "krbtgt/EXAMPLE.COM");
    }

    #[test]
    fn test_parse_service_principal_no_slash() {
        let result = parse_service_principal("justahostname");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_service_principal_strips_realm() {
        let p = parse_service_principal("HTTP/web.example.com@EXAMPLE.COM").expect("should parse");
        assert_eq!(p.to_string(), "HTTP/web.example.com");
    }
}
