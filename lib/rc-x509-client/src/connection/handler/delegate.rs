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

use std::fmt::Debug;

use tracing::debug;

use crate::{
    codec::{ClientToServer, ServerToClient},
    connection::handler::{SendToServer, ServerMessageDelegate},
};

/// Handler for [`ServerToClient`] messages (an implementation of
/// [`ServerMessageDelegate`]).
#[derive(Debug, Default)]
pub(crate) struct MessageDelegate {}

impl<IO> ServerMessageDelegate<IO> for MessageDelegate
where
    IO: SendToServer,
{
    async fn process(&mut self, msg: ServerToClient, reply: &mut IO) {
        match msg {
            ServerToClient::Ping => reply.send(ClientToServer::Pong).await.expect("pong!"),
            ServerToClient::ClientHelloAck { connection_id } => {
                debug!(?connection_id, "obtained unverified connection ID");
            }
            _ => unimplemented!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use crate::mocks::io::new_io_pair;

    use super::*;

    /// Test handling of a PING server message.
    #[tokio::test]
    async fn test_ping_pong() {
        let mut d = MessageDelegate::default();

        let (mut client, mut server) = new_io_pair();

        d.process(ServerToClient::Ping, &mut client).await;

        let got = server.recv().await.expect("must reply");
        assert_matches!(got, ClientToServer::Pong);
    }
}
