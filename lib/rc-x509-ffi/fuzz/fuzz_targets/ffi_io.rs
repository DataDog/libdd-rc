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

#![no_main]

//! This fuzzer drives the FFI interface to verify:
//!
//!   * FFI library init & free.
//!   * Driving the connection lifecycle through the FFI interface.
//!   * Data moving across the FFI boundary is safe and data is complete.
//!   * FFI send callback, and user_data context is safe.
//!   * Codecs are fully exercised, and hardened against invalid input.
//!   * Internal I/O propagation is functional (inc. I/O thread).
//!   * I/O handling primitives do not crash on invalid wire messages.
//!
//! To run run this fuzzer:
//!
//!   cargo +nightly fuzz run ffi_io -- \
//!     -timeout=2 \
//!     -malloc_limit_mb=256 \
//!     -rss_limit_mb=4096
//!
//! This will:
//!
//!   * Fail if a single call to the below fuzz target takes >2s.
//!   * Fail if a single allocation exceeds 265MiB.
//!   * Fail if the fuzzer consumes more than 4GiB of RAM (not necessarily the
//!     application using the RAM!)
//!
//! Note the RSS of the fuzzer will continuously increase and eventually hit the
//! 4GiB limit and fail, showing the vast majority of allocations in the fuzzer
//! itself (see https://github.com/rust-fuzz/cargo-fuzz/issues/270). This is a
//! fuzzer issue, not the library: if the code-under-test were leaking memory,
//! the leak sanitiser would fire as part a fuzz run.

use std::{ffi::c_void, slice};

use libfuzzer_sys::fuzz_target;
use rc_x509_ffi::*;
use rc_x509_proto::{decode, protocol::v1::ClientToServer};

use crate::test_harness::new_echo_ctx;

mod test_harness;

fuzz_target!(|data: &[u8]| {
    // Register a new testing context that parses any incoming data, and replies
    // with a fixed response for each.
    let mut ctx = new_echo_ctx();

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
    let conn = unsafe { rc_conn_new(&mut *ctx as _) };
    unsafe { rc_conn_send_callback(conn, do_send, tx_ptr as _) };
    unsafe { rc_conn_connected(conn) };

    // Push data into the client.
    let ret = unsafe { rc_conn_recv(conn, data.as_ptr(), data.len() as _) };
    assert_eq!(ret, RecvRet::Success);

    // No response is sent for an input of length 0, as it is a no-op.
    if !data.is_empty() {
        // Wait for the response payload.
        let send_data = rx.recv().expect("callback must be made");
        assert!(!send_data.is_empty());

        // Verify it is a valid ClientToServer frame (i.e data not truncated by
        // overly short "len" in send callbacks).
        let _ = decode::<ClientToServer>(send_data.as_slice()).expect("valid send payload");
    }

    // Clean up.
    //
    // After rc_conn_disconnected() returns, no more SendCb calls will be made,
    // so it is safe to reclaim the user_data Box.
    unsafe { rc_conn_disconnected(conn) };
    // Free the callback channel passed in the user_data.
    drop(unsafe { Box::from_raw(tx_ptr) });

    unsafe { rc_conn_free(conn) };
    unsafe { rc_free(Box::into_raw(ctx)) };
});
