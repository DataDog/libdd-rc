//! Test helpers for testing message handling.

use assert_matches::assert_matches;
use proptest::{prelude::*, strategy::LazyJust};
use rc_crypto::{
    certificate::id::CertId,
    connection_id::{ConnectionId, IdNonce, UntrustedConnectionId},
};
use rc_x509_trust::cert::UntrustedCertBytes;
use tokio_util::bytes::Bytes;

use crate::{
    codec::{ClientToServer, DetachedSignature, ServerToClient, tests::SAMPLE_CERT_DER},
    connection::{
        ReconnectionData,
        handler::{ServerMessageDelegate as _, delegate::MessageDelegate},
    },
    host_runtime::CorrelationId,
    mocks::io::{MockIO, MockIOServer},
    tests::arbitrary_bytes,
};

/// Drive `d` through a complete, successful handshake: read the
/// [`ClientToServer::ClientHello`] sent by `d`, derive the resulting
/// [`ConnectionId`] from the client-provided nonce, and deliver the
/// [`ServerToClient::ClientHelloAck`] response back to `d`.
pub(crate) async fn do_handshake(
    d: MessageDelegate,
    client: &mut MockIO,
    server: &mut MockIOServer,
) -> MessageDelegate {
    let d = d.send_hello(client).await;

    let client_nonce = assert_matches!(
        server.recv().await,
        Some(ClientToServer::ClientHello { client_nonce, .. }) => client_nonce
    );

    let server_nonce = IdNonce::default();
    let connection_id = ConnectionId::new(&client_nonce, server_nonce.as_bytes());

    d.process(
        Ok(ServerToClient::ClientHelloAck {
            connection_id: UntrustedConnectionId::new(
                Bytes::copy_from_slice(server_nonce.as_bytes()),
                Bytes::copy_from_slice(connection_id.as_bytes()),
            ),
        }),
        client,
    )
    .await
}

/// Generate an arbitrary ServerToClient message.
pub(crate) fn any_server_to_client() -> impl Strategy<Value = ServerToClient> {
    prop_oneof![
        arbitrary_valid_dispatch_request(),
        LazyJust::new(|| ServerToClient::Ping),
        LazyJust::new(
            || ServerToClient::CertificatePush(vec![UntrustedCertBytes::new(SAMPLE_CERT_DER)])
        ),
        LazyJust::new(|| ServerToClient::ClientHelloAck {
            connection_id: UntrustedConnectionId::new(
                Bytes::from_static(&[1, 2, 3, 4]),
                Bytes::from_static(&[5, 6, 7, 8])
            ),
        }),
        arbitrary_bytes(0..1028)
            .prop_map(|v| ServerToClient::SetReconnectionData(ReconnectionData::new(v))),
    ]
}

/// Generate a random, but valid, dispatch request.
pub(crate) fn arbitrary_valid_dispatch_request() -> impl Strategy<Value = ServerToClient> {
    (
        any::<u64>(),                                             // ID
        arbitrary_bytes(0..1028),                                 // payload
        arbitrary_bytes(CertId::MIN_LENGTH..=CertId::MAX_LENGTH), // cert ID
        arbitrary_bytes(1..1028),                                 // signature (non-empty)
    )
        .prop_map(
            |(id, payload, cert_id, signature)| ServerToClient::Dispatch {
                correlation_id: CorrelationId::new(id),
                payload,
                detached_signature: Some(DetachedSignature { cert_id, signature }),
            },
        )
}

/// Generate an arbitrary [`ServerToClient::Dispatch`] that is logically
/// malformed in such a way that it causes the client to raise a protocol
/// error.
pub(crate) fn arbitrary_invalid_dispatch_request() -> impl Strategy<Value = ServerToClient> {
    prop_oneof![
        // No signature:
        arbitrary_valid_dispatch_request().prop_map(|mut v| {
            match &mut v {
                ServerToClient::Dispatch {
                    detached_signature, ..
                } => *detached_signature = None,
                _ => unreachable!(),
            };

            v
        }),
        // Cert ID too small / empty:
        (
            arbitrary_valid_dispatch_request(),
            arbitrary_bytes(0..CertId::MIN_LENGTH)
        )
            .prop_map(|(mut v, id)| {
                match &mut v {
                    ServerToClient::Dispatch {
                        detached_signature: Some(DetachedSignature { cert_id, .. }),
                        ..
                    } => *cert_id = id,
                    _ => unreachable!(),
                };

                v
            }),
        // Cert ID too big:
        (
            arbitrary_valid_dispatch_request(),
            arbitrary_bytes((CertId::MAX_LENGTH + 1)..1028)
        )
            .prop_map(|(mut v, id)| {
                match &mut v {
                    ServerToClient::Dispatch {
                        detached_signature: Some(DetachedSignature { cert_id, .. }),
                        ..
                    } => *cert_id = id,
                    _ => unreachable!(),
                };

                v
            }),
        // Signature empty
        arbitrary_valid_dispatch_request().prop_map(|mut v| {
            match &mut v {
                ServerToClient::Dispatch {
                    detached_signature: Some(DetachedSignature { signature, .. }),
                    ..
                } => *signature = Bytes::default(),
                _ => unreachable!(),
            };

            v
        }),
    ]
}

/// Returns true if the message yielded by `input` is a message type that
/// should be accepted by the client at any time.
pub(crate) fn filter_allowed_at_any_time(
    input: impl Strategy<Value = ServerToClient>,
) -> impl Strategy<Value = ServerToClient> {
    filter_implemented(input).prop_filter("allowed at any time filter", |v| match v {
        // These message types have ordering restrictions:
        ServerToClient::Dispatch { .. } | ServerToClient::ClientHelloAck { .. } => false,
        _ => true,
    })
}

/// Returns true if the message yielded by `input` is a message type that
/// should be accepted by the client after the handshake.
pub(crate) fn filter_allowed_after_handshake(
    input: impl Strategy<Value = ServerToClient>,
) -> impl Strategy<Value = ServerToClient> {
    input.prop_filter("allowed after handshake filter", |v| {
        !matches!(v, ServerToClient::ClientHelloAck { .. })
    })
}

// A temporary filter until all handlers are implemented.
pub(crate) fn filter_implemented(
    input: impl Strategy<Value = ServerToClient>,
) -> impl Strategy<Value = ServerToClient> {
    input.prop_filter("implemented filter", |v| {
        !matches!(
            v,
            ServerToClient::CertificatePush(..) | ServerToClient::SetReconnectionData(..)
        )
    })
}

/// Returns true if a server sending `v` should expect a reply.
pub(crate) fn has_reply(v: &ServerToClient) -> bool {
    match v {
        ServerToClient::Ping | ServerToClient::Dispatch { .. } => true,
        ServerToClient::CertificatePush(..)
        | ServerToClient::ClientHelloAck { .. }
        | ServerToClient::SetReconnectionData(..) => false,
    }
}
