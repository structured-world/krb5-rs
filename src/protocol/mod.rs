//! Kerberos protocol exchange state machines.
//!
//! This module implements step-based AS and TGS protocol exchanges
//! following MIT krb5's design. The caller drives the loop and
//! controls transport — state machines only produce outbound messages
//! and consume inbound responses.

mod as_exchange;
mod credential;
mod error_codes;
mod preauth;
mod tgs_exchange;
mod validate;

pub use as_exchange::{AsExchange, AsExchangeConfig, StepResult};
pub use credential::{Credential, TicketTimes};
pub use error_codes::ErrorCode;
pub use preauth::{PreauthContext, PreauthPlugin};
pub use tgs_exchange::{TgsExchange, TgsOptions, TgsStepResult};
