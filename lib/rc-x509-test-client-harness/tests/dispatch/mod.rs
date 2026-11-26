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

//! Tests specific to dispatch requests.
//!
//! This module is referenced from the top-level `integration.rs` file, instead
//! of being a file next to it, so that there's only one test binary to link
//! during test compilation, which speeds up the dev change / test cycle.

mod prop_generators;

use std::{collections::HashSet, iter};

use assert_matches::assert_matches;
use proptest::prelude::*;
use rc_x509_client::{
    codec::{ClientToServer, DispatchViolation, ProtocolError},
    host_runtime::CorrelationId,
};
use rc_x509_proto::{magic_tunnel::v1::magic_tunnel_response, protocol::v1};
use rc_x509_test_client_harness::{
    TestClientBuilder,
    client::{TestConn, conn_id_to_proto},
    logging,
};
use rc_x509_test_helpers::test_issuer::{TestCA, TestChain, ValidChain, arbitrary_chain};
use rc_x509_trust::chain::MAX_INTERMEDIATES;
use tokio_util::bytes::Bytes;

use crate::dispatch::prop_generators::{
    DispatchDefect, arbitrary_fatal_chain_defect, arbitrary_fatal_dispatch_defect,
};

const URI: &str = "rc.x509.magic_tunnel.remote_config.v1.DebugService/Ping";

static CA: TestCA = TestCA::new();

/// A test that exercises the client dispatch path and dispatch response path.
#[tokio::test]
async fn test_dispatch_happy_path() {
    logging::init();

    const APPLICATION_REQUEST_PAYLOAD: Bytes = Bytes::from_static(&[42, 42, 42, 42]);
    const APPLICATION_RESPONSE_PAYLOAD: Bytes = Bytes::from_static(&[13, 13, 13, 13]);

    let chain = TestChain::default();
    let mut client = TestClientBuilder::default()
        .with_testing_roots(chain.root())
        .build();
    let mut conn = client.new_connection().await;

    // Push all the necessary certs to the client.
    conn.push_chain(&chain).await;

    // Perform the connection handshake to obtain the connection ID.
    let connection_id = conn_id_to_proto(conn.perform_handshake().await);

    // 1. The server sends a dispatch request:
    let request = conn.new_magic_tunnel_dispatch(
        CorrelationId::new(42),
        &chain.leaf,
        URI,
        APPLICATION_REQUEST_PAYLOAD,
    );
    conn.send(Ok(request)).await;

    // 2. The application receives the application payload, tagged with the
    //    correct uri for routing purposes:
    let dispatch = {
        let dispatch = conn.get_application_dispatch().await;

        // The payload must be routed for the correct connection, and be a
        // magic tunnel request tagged with the correct uri / payload
        // bytes for routing purposes:
        let (uri, payload) = dispatch.assume_magic_tunnel(&connection_id);
        assert_eq!(uri, URI);
        assert_eq!(payload, APPLICATION_REQUEST_PAYLOAD);

        dispatch
    };

    let correlation_id = dispatch.correlation_id();

    // 3. The application generates a response:
    dispatch
        .respond_magic_tunnel(magic_tunnel_response::Result::Response(
            APPLICATION_RESPONSE_PAYLOAD,
        ))
        .await;

    // 4. The client must push the application's dispatch response to the
    //    server, correlated with the original request and carrying the
    //    application's response bytes:
    let result = conn
        .recv()
        .await
        .assume_magic_tunnel_response(correlation_id);
    let application_response = assert_matches!(
        result,
        magic_tunnel_response::Result::Response(v) => v
    );
    assert_eq!(application_response, APPLICATION_RESPONSE_PAYLOAD);

    // Signal the client library shutdown:
    client.shutdown().await;
}

/// A test that exercises the client dispatch path when the application reports
/// a handler error for the dispatch request.
#[tokio::test]
async fn test_dispatch_handler_error() {
    logging::init();

    const APPLICATION_REQUEST_PAYLOAD: Bytes = Bytes::from_static(&[42, 42, 42, 42]);
    const HANDLER_ERROR: &str = "handler exploded";

    let chain = TestChain::default();
    let mut client = TestClientBuilder::default()
        .with_testing_roots(chain.root())
        .build();
    let mut conn = client.new_connection().await;

    conn.push_chain(&chain).await;

    // Perform the connection handshake to obtain the connection ID.
    let connection_id = conn_id_to_proto(conn.perform_handshake().await);

    // 1. The server sends a dispatch request:
    let request = conn.new_magic_tunnel_dispatch(
        CorrelationId::new(42),
        &chain.leaf,
        URI,
        APPLICATION_REQUEST_PAYLOAD,
    );
    conn.send(Ok(request)).await;

    // 2. The application receives the application payload, tagged with the
    //    correct URI for routing purposes:
    let dispatch: rc_x509_test_client_harness::client::TestDispatch = {
        let dispatch = conn.get_application_dispatch().await;

        let (uri, payload) = dispatch.assume_magic_tunnel(&connection_id);
        assert_eq!(uri, URI);
        assert_eq!(payload, APPLICATION_REQUEST_PAYLOAD);

        dispatch
    };

    let correlation_id = dispatch.correlation_id();

    // 3. The application reports a handler error:
    dispatch
        .respond_magic_tunnel(magic_tunnel_response::Result::HandlerError(
            HANDLER_ERROR.to_string(),
        ))
        .await;

    // 4. The client must push the handler error to the server, correlated
    //    with the original request:
    let result = conn
        .recv()
        .await
        .assume_magic_tunnel_response(correlation_id);
    let handler_error = assert_matches!(
        result,
        magic_tunnel_response::Result::HandlerError(v) => v
    );
    assert_eq!(handler_error, HANDLER_ERROR);

    // Signal the client library shutdown:
    client.shutdown().await;
}

proptest! {
    /// A defective chain always causes a protocol error to be raised. The
    /// client then stops processing further messages.
    #[test]
    fn prop_fatal_chain_defect(
        chain in arbitrary_fatal_chain_defect(&CA, 2..=5_u8),
    ) {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(test_prop_fatal_chain_defect(chain));
    }

    /// A dispatch request with a defect (missing / malformed / mismatched
    /// signature, modified payload, wrong connection ID, etc) for a valid chain
    /// always causes the corresponding protocol error to be raised.
    #[test]
    fn prop_fatal_dispatch_defect(
        chain in arbitrary_chain(&CA, 1..=3_u8, ValidChain::default()),
        defect in arbitrary_fatal_dispatch_defect(),
    ) {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(test_prop_fatal_dispatch_defect(chain, defect));
    }

    /// This test asserts the correct functioning of dispatch requests that have
    /// to be deferred due to necessary certificates missing on the client.
    ///
    /// The test setup:
    ///
    ///   * Generates two chains from the same root CA.
    ///   * Chain A is pushed to the client in full; all dispatches using chain
    ///     A should immediately complete (all state is local to the client).
    ///   * Chain B is only partially pushed to the client (randomised subset);
    ///     any dispatches using chain B will be deferred and a ChainFetch will
    ///     be generated for the missing cert.
    ///
    /// Then an incremental discovery of the missing certs runs, simulating the
    /// worst case discovery where the server only provides the single missing
    /// cert instead of the full chain in the first response:
    ///
    ///   * Start a dispatch for chain B.
    ///   * Read the ChainFetch request it generates.
    ///   * Assert the requested cert is part of chain B and isn't known to the
    ///     client, and push the requested cert to the client.
    ///   * Client generates next ChainFetch for next missing cert, repeat...
    ///
    /// Eventually all certs in chain B are known by the client, and the
    /// dispatch completes successfully. This ensures a dispatch can be "parked"
    /// repeatedly to fill gaps in the local cache, but eventually completes. At
    /// all times a dispatch for chain A MUST complete (no head-of-line blocking
    /// / cross-dispatch queuing).
    #[test]
    fn prop_deferred_dispatch(
        chain_a in arbitrary_chain(&CA, 0..=3_u8, ValidChain::default()),
        chain_b in arbitrary_chain(&CA, 0..=5_u8, ValidChain::default()),
        b_pushed in prop::collection::vec(any::<prop::sample::Index>(), 0..10),
    ) {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(test_prop_deferred_dispatch(chain_a, chain_b, b_pushed));
    }

    /// A chain discovery for a chain with more than [`MAX_INTERMEDIATES`] fails
    /// eagerly after asking for [`MAX_INTERMEDIATES`] rather than trying to
    /// discover an endless chain of certs, bounding dispatch deferral exec.
    #[test]
    fn prop_excessively_long_chain(
        chain in arbitrary_chain(
            &CA,
            (MAX_INTERMEDIATES as u8 + 1)..=50,
            ValidChain::default()
        ),
    ) {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(test_prop_excessively_long_chain(chain));
    }
}

async fn test_prop_fatal_chain_defect(chain: TestChain) {
    logging::init();

    const APPLICATION_REQUEST_PAYLOAD: Bytes = Bytes::from_static(&[42, 42, 42, 42]);

    let mut client = TestClientBuilder::default()
        .with_testing_roots(chain.root())
        .build();
    let mut conn = client.new_connection().await;

    // Pushing the certs succeeds - they're only identified as "bad" at
    // validation time.
    conn.push_chain(&chain).await;

    // Perform the connection handshake to obtain the connection ID and drive
    // the client into the ready state.
    let _connection_id = conn_id_to_proto(conn.perform_handshake().await);

    // 1. The server sends a dispatch request:
    let request = conn.new_magic_tunnel_dispatch(
        CorrelationId::new(42),
        &chain.leaf,
        URI,
        APPLICATION_REQUEST_PAYLOAD,
    );
    conn.send(Ok(request)).await;

    // 2. Because the chain is invalid, the client MUST return an fatal protocol
    //    error.
    let response = conn.recv().await.into_inner();
    assert_matches!(
        response,
        ClientToServer::ProtocolError {
            reason: _,
            is_handshake_complete: true
        }
    );

    // Signal the client library shutdown:
    client.shutdown().await;
}

async fn test_prop_fatal_dispatch_defect(chain: TestChain, defect: DispatchDefect) {
    logging::init();

    const APPLICATION_REQUEST_PAYLOAD: Bytes = Bytes::from_static(&[42, 42, 42, 42]);
    const CORRELATION_ID: CorrelationId = CorrelationId::new(42);

    let mut client = TestClientBuilder::default()
        .with_testing_roots(chain.root())
        .build();
    let mut conn = client.new_connection().await;

    // Push the (valid) chain so that verification never has to be deferred
    // to fetch a missing certificate.
    conn.push_chain(&chain).await;

    // Perform the connection handshake to obtain the connection ID and drive
    // the client into the ready state.
    let _connection_id = conn_id_to_proto(conn.perform_handshake().await);

    // 1. The server sends a defective dispatch request:
    let mut request = conn.new_magic_tunnel_dispatch(
        CORRELATION_ID,
        &chain.leaf,
        URI,
        APPLICATION_REQUEST_PAYLOAD,
    );
    defect.apply(&mut request, &chain);
    conn.send(Ok(request)).await;

    // 2. The client MUST return a fatal protocol error for this dispatch
    //    request, caused by the defect:
    let reason = assert_matches!(
        conn.recv().await.into_inner(),
        ClientToServer::ProtocolError {
            reason,
            is_handshake_complete: true
        } => reason
    );

    // 3. The reason identifies the dispatch failure:
    let violation = assert_matches!(
        reason,
        ProtocolError::Dispatch(correlation_id, v) => {
            assert_eq!(correlation_id, CORRELATION_ID);
            v
        }
    );
    defect.assert_violation(violation);

    // Signal the client library shutdown:
    client.shutdown().await;
}

async fn test_prop_deferred_dispatch(
    chain_a: TestChain,
    chain_b: TestChain,
    chain_b_known_sample: Vec<prop::sample::Index>,
) {
    logging::init();

    const PAYLOAD_A: Bytes = Bytes::from_static(&[42, 42, 42, 42]);
    const PAYLOAD_B: Bytes = Bytes::from_static(&[13, 13, 13, 13]);

    let mut client = TestClientBuilder::default()
        .with_testing_roots(chain_a.root()) // Both chains use same CA.
        .build();

    let mut conn = client.new_connection().await;

    // Push all of chain A - this will be used to verify that dispatches
    // deferred for cert lookup do not block dispatches that can complete
    // immediately.
    conn.push_chain(&chain_a).await;

    // Collect the full set of Certificate for chain_b.
    let certs_b = chain_b
        .intermediates
        .iter()
        .chain(iter::once(&chain_b.leaf))
        .map(|v| v.cert().clone())
        .collect::<Vec<_>>();

    // Partially push the content of chain_b to the client, and return the certs
    // in chain_b that the client doesn't know about.
    let mut missing_certs = {
        // Select a subset of certs_b (selected by chain_b_known_sample) to push
        // to the client:
        let pushed_idx = chain_b_known_sample
            .iter()
            .map(|v| v.index(certs_b.len()))
            .collect::<HashSet<_>>();
        if !pushed_idx.is_empty() {
            conn.push_certs(pushed_idx.iter().map(|&i| &certs_b[i]))
                .await;
        }

        // Return the set of certificates in chain_b the client does not know
        // about.
        certs_b
            .iter()
            .enumerate()
            .filter(|(i, _)| !pushed_idx.contains(i))
            .map(|(_, v)| v.clone())
            .collect::<Vec<_>>()
    };

    // Perform a handshake to generate the connection ID and get the client into
    // the "active" state where it will accept dispatches.
    let connection_id = conn_id_to_proto(conn.perform_handshake().await);

    // Helper to create sequential correlation IDs.
    let mut make_correlation_id = (0..).map(CorrelationId::new);

    /// Helper fn to send a dispatch request signed by the `chain_a` leaf, and
    /// assert it is verified and delivered to the application immediately.
    async fn dispatch_chain_a(
        conn: &mut TestConn,
        connection_id: &v1::ConnectionId,
        correlation_id: CorrelationId,
        chain_a: &TestChain,
    ) {
        let request = conn.new_magic_tunnel_dispatch(correlation_id, &chain_a.leaf, URI, PAYLOAD_A);
        conn.send(Ok(request)).await;

        let dispatch = conn.get_application_dispatch().await;
        assert_eq!(dispatch.correlation_id(), correlation_id);
        let (uri, payload) = dispatch.assume_magic_tunnel(connection_id);
        assert_eq!(uri, URI);
        assert_eq!(payload, PAYLOAD_A);
    }

    // 1. A dispatch for chain A succeeds.
    dispatch_chain_a(
        &mut conn,
        &connection_id,
        make_correlation_id.next().unwrap(),
        &chain_a,
    )
    .await;

    // 2. A dispatch for chain B is sent, which can only be verified once all
    //    of chain B is known to the client.
    let correlation_id_b = make_correlation_id.next().unwrap();
    let request = conn.new_magic_tunnel_dispatch(correlation_id_b, &chain_b.leaf, URI, PAYLOAD_B);
    conn.send(Ok(request)).await;

    // 3. While certs from chain B are missing, the client MUST ask for one of
    //    them.
    while !missing_certs.is_empty() {
        let cert_id = assert_matches!(
            conn.recv().await.into_inner(),
            ClientToServer::ChainFetch { cert_id } => cert_id
        );

        // The requested cert MUST be one of the certs the client is missing.
        let idx = missing_certs
            .iter()
            .position(|v| {
                v.cert_id().as_dangerous_comparable().as_bytes()
                    == cert_id.as_dangerous_comparable().as_bytes()
            })
            .expect("client requested a cert that is not missing from chain B");

        // The deferred chain B dispatch does not block a chain A dispatch from
        // completing:
        dispatch_chain_a(
            &mut conn,
            &connection_id,
            make_correlation_id.next().unwrap(),
            &chain_a,
        )
        .await;

        // Push the requested cert to the client:
        let cert = missing_certs.swap_remove(idx);
        conn.push_certs([&cert]).await;
    }

    // 4. Once all of chain B is known, the deferred dispatch is verified and
    //    delivered to the application.
    let dispatch = conn.get_application_dispatch().await;
    assert_eq!(dispatch.correlation_id(), correlation_id_b);
    let (uri, payload) = dispatch.assume_magic_tunnel(&connection_id);
    assert_eq!(uri, URI);
    assert_eq!(payload, PAYLOAD_B);

    // And chain A continues to work.
    dispatch_chain_a(
        &mut conn,
        &connection_id,
        make_correlation_id.next().unwrap(),
        &chain_a,
    )
    .await;

    // Signal the client library shutdown:
    client.shutdown().await;
}

async fn test_prop_excessively_long_chain(chain: TestChain) {
    logging::init();

    const APPLICATION_REQUEST_PAYLOAD: Bytes = Bytes::from_static(&[42, 42, 42, 42]);
    const CORRELATION_ID: CorrelationId = CorrelationId::new(42);

    let mut client = TestClientBuilder::default()
        .with_testing_roots(chain.root())
        .build();
    let mut conn = client.new_connection().await;

    // No certs are pushed to the client before the handshake.
    let _connection_id = conn_id_to_proto(conn.perform_handshake().await);

    // 1. The server sends a dispatch request signed by the leaf of an insanely
    //    long chain:
    let request = conn.new_magic_tunnel_dispatch(
        CORRELATION_ID,
        &chain.leaf,
        URI,
        APPLICATION_REQUEST_PAYLOAD,
    );
    conn.send(Ok(request)).await;

    // 2. The client requests the leaf, followed by each intermediate in the
    //    chain (ordered leaf to root) until the chain exceeds
    //    MAX_INTERMEDIATES.
    let expected = iter::once(&chain.leaf)
        .chain(chain.intermediates.iter().rev())
        .take(MAX_INTERMEDIATES + 1);
    for want in expected {
        let cert_id = assert_matches!(
            conn.recv().await.into_inner(),
            ClientToServer::ChainFetch { cert_id } => cert_id
        );
        assert_eq!(
            cert_id.as_dangerous_comparable().as_bytes(),
            want.cert().cert_id().as_dangerous_comparable().as_bytes()
        );

        conn.push_certs([want.cert()]).await;
    }

    // 3. The chain is now known to exceed MAX_INTERMEDIATES, and the client
    //    MUST reject the dispatch without requesting any further certs.
    let leaf_cert_id = assert_matches!(
        conn.recv().await.into_inner(),
        ClientToServer::ProtocolError {
            reason: ProtocolError::Dispatch(
                CORRELATION_ID,
                DispatchViolation::ExcessivelyLongChain { leaf_cert_id }
            ),
            is_handshake_complete: true
        } => leaf_cert_id
    );
    assert_eq!(
        leaf_cert_id,
        chain
            .leaf
            .cert()
            .cert_id()
            .as_dangerous_comparable()
            .as_bytes()
    );

    // Signal the client library shutdown:
    client.shutdown().await;
}
