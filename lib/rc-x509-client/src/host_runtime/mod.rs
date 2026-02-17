//! Boundary interface between this client library, and a host layer capable of
//! performing I/O, possibly called via FFI.

mod api;
mod connection;
mod correlation_id;

pub(crate) use api::*;
pub(crate) use connection::*;
pub(crate) use correlation_id::*;
