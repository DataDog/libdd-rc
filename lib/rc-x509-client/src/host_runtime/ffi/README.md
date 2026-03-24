# FFI Interface

This module defines a C compatible API for use as an FFI interface to the X509
client library.

## Design

This library aims to encapsulate all the state, logic, communication protocol
and message encoding details necessary to communicate with the RC delivery
backend.

All I/O is delegated to the host runtime which is responsible for creating a
connection to the RC backend, informing the client library of connection
lifecycle events (e.g. disconnects) while brokering data received from and sent
to the RC backend.

### FFI Isolation

The FFI system is isolated from the rest of the library; it is designed to be a
thin layer that "bridges" the unsafe FFI interface into the rest of the system
in order to simplify the integration code and FFI ownership semantics, and
therefore minimise bug risk.

All interaction with the non-FFI parts of the library are bridged through
channels:

  * Connection lifecycle events ([`ConnectionEvent`]) pass through a per-[`Ctx`]
    channel, which the library [`entrypoint`] consumes to react to FFI-driven
    connection state changes.

  * Each connection initialised and marked as ready to perform I/O by the FFI
    interface ([`FFIConnection`]) has it's own [`IOHandle`], through which
    payloads are exchanged with the FFI layer, and in turn, FFI host.



## Example Usage

An example using the FFI interface from rust:

```rust
use std::{ptr, ffi::c_void};
use rc_x509_client::host_runtime::ffi::*;

// Initialise the library Ctx and obtain a handle to this library instance
let ctx = unsafe { rc_init() };

// Initialising a new connection
let conn = unsafe { rc_conn_new(ctx) };

// Configure the callback the library uses to ask the FFI host to forward data
// to the RC server.
//
// The "user_data" pointer is set by the caller, and provided to all subsequent
// callback invocations.
unsafe extern "C" fn do_send(
  _data: *const u8,
  _length: u32,
  _user_data: *const c_void
) -> SendRet {
  // Host sends data using native sockets here.
	SendRet::Success
}
unsafe { rc_conn_send_callback(conn, do_send, ptr::null()) };

// Mark the connection as available.
unsafe { rc_conn_connected(conn) };

//
// At this point, I/O is allowed to flow in either direction.
//

// Clean up:
unsafe { rc_conn_disconnected(conn) };
unsafe { rc_conn_free(conn) };
unsafe { rc_free(ctx) };
```
