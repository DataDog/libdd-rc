# rc-x509-proto

This crate holds the protobuf definitions that make up the core delivery
protocol, and the features provided by it.

The [`protocol.proto`] file defines the request / response types exchanged between
the RC delivery backend servers and the RC client.

The [`magic_tunnel`] folder contains definitions that support the Magic Tunnel
feature.

[`protocol.proto`]: protos/protocol.proto
[`magic_tunnel`]: protos/magic_tunnel/
