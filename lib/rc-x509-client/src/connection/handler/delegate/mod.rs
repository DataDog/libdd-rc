//! This module is responsible for processing [`ServerToClient`] messages from
//! the backend.
//!
//! [`ServerToClient`]: rc_x509_proto::protocol::v1::ServerToClient

mod fsm;
mod message_delegate;
mod retry;
mod state;
mod traits;

pub(crate) use message_delegate::MessageDelegate;
pub(super) use retry::retry_send;
