use std::fmt::Debug;

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
