//! Message (de-)serialisation codec implementations.
//!
//! This module defines the message types used by this application, and their
//! on-wire representation.

mod client_to_server;
mod server_to_client;

pub(crate) use client_to_server::*;
pub(crate) use server_to_client::*;
