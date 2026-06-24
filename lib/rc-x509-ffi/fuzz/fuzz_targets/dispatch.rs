// Copyright 2026-Present Datadog, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! This fuzzer drives the "dispatch" workflow, where the client receives a
//! message that instructs it to pass a payload to the host application and
//! return the response:
//!
//!   1. [Server -> Client]: sends [`v1::DispatchRequest`]
//!   2. [Client -> FFI]: invokes the dispatcher callback registered to the
//!      connection.
//!   3. [FFI -> FFI]: host application processes the message.
//!   4. [FFI -> Client]: calls [`rc_conn_dispatch_result()`] to pass the async
//!      dispatch response back into the client library.
//!   5. [Client -> Server]: returns the result of the dispatch.
//!
//! This fuzz test verifies:
//!
//!   * FFI library init + free.
//!   * Connection init + dispatch + respond + free.
//!   * Data moving across the boundary is safe, and data is complete.
//!   * The above request / response flow is followed.
//!   * Correlation and data is propagated through the client in either
//!     direction correctly (e.g. does not modify the correlation ID).
//!   * Internal dispatch subsystem is functional (inc. dispatch thread).
//!   * The client library tolerates invalid dispatch response data provided by
//!     the FFI host.
//!
//! [`v1::DispatchRequest`]: rc_x509_proto::protocol::v1
//! [`rc_conn_dispatch_result`]: rc_x509_ffi::rc_conn_dispatch_result

#![no_main]

use std::{ffi::c_void, slice};

use futures::{Stream, StreamExt, pin_mut};
use libfuzzer_sys::fuzz_target;
use rc_x509_client::{
    ShutdownSignal, codec,
    connection::{ConnectionEvent, ConnectionUpdate},
    dispatch::{Dispatch, DispatchPublisher},
    entrypoint::LibraryEntrypoint,
    host_runtime::{Connection, CorrelationId},
};
use rc_x509_ffi::*;
use rc_x509_proto::{decode, protocol::v1};

fuzz_target!(|v: (&[u8], &[u8])| {
    // Incoming data from the server containing a dispatch request.
    let message = v.0;

    // DispatchResult reply sent from the application host to the client library, and ultimately to the backend server.
    let response = v.1;

    // Define a dispatch callback that transmits the payload it is passing back
    // to the main test thread to assert against.
    unsafe extern "C" fn do_dispatch(
        correlation_id: u64,
        data: *const u8,
        length: u32,
        user_data: *const c_void,
    ) -> DispatchRet {
        let got_data = unsafe { slice::from_raw_parts(data, length as _) }.to_vec();
        let got_tx = unsafe { &*(user_data as *const std::sync::mpsc::Sender<(u64, Vec<u8>)>) };

        // Signal the callback was executed.
        got_tx
            .send((correlation_id, got_data))
            .expect("must be waiting");

        DispatchRet::Success
    }

    // The channel over which dispatch callbacks are transmitted by the
    // do_dispatch callback to the test thread.
    let (dispatch_tx, dispatch_rx) = std::sync::mpsc::channel::<(u64, Vec<u8>)>();
    let dispatch_tx = Box::new(dispatch_tx);
    let dispatch_tx_ptr = Box::into_raw(dispatch_tx);

    // Register a new testing context that parses any incoming data, and replies
    // with a fixed response for each.
    let mut ctx = new_ctx();

    // A channel to notify the main thread that the send callback succeeded, and
    // provide the payload it saw for verification.
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let tx = Box::new(tx);

    // Send callback to capture the response.
    unsafe extern "C" fn do_send(
        data: *const u8,
        length: u32,
        user_data: *const c_void,
    ) -> SendRet {
        // Uncomment this to see a OOB read caught by the fuzzer, or change it
        // to a -1 to see the decode assert fire when parsing the captured
        // payload.
        // let length = length + 1;

        // Copy the payload being sent.
        //
        // Copying involves reading each byte in the callback payload, and this
        // allows ASAN to catch out-of-bounds reads (e.g. by incorrect "len"
        // values in the callback).
        let got_data = unsafe { slice::from_raw_parts(data, length as _) }.to_vec();

        // Borrow the sender from user_data rather than taking ownership, so
        // that the fuzz harness retains responsibility for freeing it. This
        // avoids leaking the Box when the callback is never invoked (e.g. empty
        // input) and avoids a use-after-free if called more than once.
        let got_tx = unsafe { &*(user_data as *const std::sync::mpsc::Sender<Vec<u8>>) };

        got_tx.send(got_data).unwrap(); // Signal the callback was executed.

        SendRet::Success
    }

    // Initialise the connection.
    let tx_ptr = Box::into_raw(tx);
    let conn = unsafe { rc_conn_new(&mut *ctx as _, do_dispatch, dispatch_tx_ptr as _) };
    unsafe { rc_conn_send_callback(conn, do_send, tx_ptr as _) };
    unsafe { rc_conn_connected(conn) };

    // Push data into the client.
    let ret = unsafe { rc_conn_recv(conn, message.as_ptr(), message.len() as _) };
    assert_eq!(ret, RecvRet::Success);

    // At this point, the behaviour of the client library diverges based on what
    // payload was sent.
    let payload = decode::<v1::ServerToClient>(message);

    match payload.map(|v| v.message) {
        Ok(Some(v1::server_to_client::Message::Dispatch(v1::DispatchRequest {
            correlation_id: server_sent_id,
            payload: Some(server_sent_payload),
        }))) => {
            // The client library will emit a Dispatch callback for this message
            // type.
            let (callback_id, callback_data) = dispatch_rx.recv().expect("sender not dropped");

            // The dispatch callback should have received the same correlation
            // ID as the one that the server sent:
            assert_eq!(server_sent_id, callback_id);

            // Likewise the payload must match.
            //
            // NOTE: this relies on deterministic serialisation, which is only
            // true under some conditions.
            let mut original_buf = vec![];
            server_sent_payload.encode(&mut original_buf);
            assert_eq!(original_buf, callback_data);

            // This thread must return a DispatchResponse to the client.
            unsafe {
                rc_conn_dispatch_result(
                    conn,
                    callback_id,
                    response.as_ptr(),
                    response.len() as u32,
                );
            }

            // And in response, the client library will forward a DispatchResult
            // message to the backend server.
            let response_sent_to_server = rx
                .recv()
                .expect("must always respond to server even if payload or response is invalid");

            // The client library deserialises the response bytes and
            // re-serialises them when building the outgoing proto message.
            // Invalid bytes are mapped to an error result. Reconstruct the
            // expected wire message to compare against what was actually sent.
            let expected = match decode::<v1::DispatchResponsePayload>(response) {
                Ok(payload) => codec::ClientToServer::DispatchResponse {
                    correlation_id: CorrelationId::new(callback_id),
                    result: v1::dispatch_response::Result::Payload(payload),
                },
                Err(_) => codec::ClientToServer::DispatchResponse {
                    correlation_id: CorrelationId::new(callback_id),
                    result: v1::dispatch_response::Result::Error(
                        v1::dispatch_response::DispatchError::Unspecified as i32,
                    ),
                },
            };
            assert_eq!(Vec::from(expected), response_sent_to_server);
        }
        _ => { /* Nothing happens */ }
    }

    // Clean up.
    //
    // After rc_conn_disconnected() returns, no more SendCb calls will be made,
    // so it is safe to reclaim the user_data Box.
    unsafe { rc_conn_disconnected(conn) };
    // Free the callback channels passed in the user_data fields.
    drop(unsafe { Box::from_raw(tx_ptr) });
    drop(unsafe { Box::from_raw(dispatch_tx_ptr) });

    unsafe { rc_conn_free(conn) };
    unsafe { rc_free(Box::into_raw(ctx)) };
});

/// A [`DispatchEndpoint`] is designed to exercise the FFI layer dispatch and
/// dispatch response methods.
#[derive(Debug)]
struct DispatchEndpoint;
impl<IO> LibraryEntrypoint<IO> for DispatchEndpoint
where
    IO: Connection,
{
    async fn entrypoint(
        self,
        _shutdown: ShutdownSignal,
        conn_events: impl Stream<Item = ConnectionUpdate<IO>> + Send + Sync + 'static,
    ) {
        pin_mut!(conn_events);

        while let Some(event) = conn_events.next().await {
            if let ConnectionEvent::Connected(io, dispatch) = event.into_event() {
                tokio::task::spawn(handle_conn(io, dispatch));
            }
        }
    }
}

async fn handle_conn<IO>(mut io: IO, mut dispatch: DispatchPublisher)
where
    IO: Connection,
{
    let recv = io.take_recv_stream().expect("first use of connection I/O");
    pin_mut!(recv);

    let mut dispatch_responses = dispatch.take_recv_stream().expect("first use");

    while let Some(v) = recv.next().await {
        match v {
            Ok(codec::ServerToClient::Dispatch {
                correlation_id,
                payload,
            }) => {
                // Dispatch to the FFI host.
                dispatch
                    .dispatch(Dispatch {
                        correlation_id,
                        payload,
                    })
                    .expect("FFI host must consume dispatch messages");

                // then fall through
            }
            _ => {
                // only dispatch messages are acted on.
                continue;
            }
        }

        // Block waiting for a dispatch response.
        let resp = dispatch_responses.next().await.expect("response");

        // And transmit the response to the backend server.
        let result = match resp.result {
            Ok(payload) => v1::dispatch_response::Result::Payload(payload),
            Err(_) => v1::dispatch_response::Result::Error(
                v1::dispatch_response::DispatchError::Unspecified as i32,
            ),
        };
        io.send(codec::ClientToServer::DispatchResponse {
            correlation_id: resp.correlation_id,
            result,
        })
        .await
        .expect("handle must be alive prior to shutdown");
    }
}

/// Construct a [`Ctx`] that uses a [`DispatchEndpoint`] instead of the default
/// library entrypoint.
fn new_ctx() -> Box<Ctx> {
    Ctx::new(DispatchEndpoint)
}
