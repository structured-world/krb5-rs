//! Kerberos AS (Authentication Service) exchange state machine.
//!
//! This module implements a step-based AS protocol exchange pattern
//! following MIT krb5's `krb5_init_creds_step()` design. The caller
//! drives the loop and controls transport — the state machine only
//! produces outbound messages and consumes inbound responses.

mod as_exchange;
mod credential;
mod error_codes;
mod preauth;
mod validate;

pub use as_exchange::{AsExchange, AsExchangeConfig, StepResult};
pub use credential::{Credential, TicketTimes};
pub use error_codes::ErrorCode;
pub use preauth::{PreauthContext, PreauthPlugin};
