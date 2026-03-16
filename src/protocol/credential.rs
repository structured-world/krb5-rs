//! Kerberos credential (ticket + metadata).

use crate::types::{
    AuthorizationDataElement, EncryptionKey, HostAddress, KerberosFlags, KerberosTime,
    PrincipalName, Ticket, TicketFlags,
};

/// Times associated with a Kerberos ticket.
#[derive(Debug, Clone)]
pub struct TicketTimes {
    /// Time of initial authentication.
    pub authtime: KerberosTime,
    /// Start of ticket validity (if absent, same as authtime).
    pub starttime: Option<KerberosTime>,
    /// Expiration time.
    pub endtime: KerberosTime,
    /// Renewal expiration (only if ticket is renewable).
    pub renew_till: Option<KerberosTime>,
}

/// A Kerberos credential: a ticket plus its associated metadata.
///
/// Produced by a successful AS or TGS exchange.
#[derive(Debug, Clone)]
pub struct Credential {
    /// Client principal (owner of this credential).
    pub client: PrincipalName,
    /// Client realm.
    pub crealm: String,
    /// Server principal (service this ticket is for).
    pub server: PrincipalName,
    /// Server realm.
    pub srealm: String,
    /// Session key for communication with the server.
    pub session_key: EncryptionKey,
    /// Ticket times.
    pub times: TicketTimes,
    /// The opaque ticket blob (sent to the server in AP-REQ).
    pub ticket: Ticket,
    /// Ticket flags.
    pub flags: KerberosFlags<TicketFlags>,
    /// Client addresses (if ticket is address-restricted).
    pub addresses: Option<Vec<HostAddress>>,
    /// Authorization data embedded in the ticket.
    pub authdata: Option<Vec<AuthorizationDataElement>>,
}
