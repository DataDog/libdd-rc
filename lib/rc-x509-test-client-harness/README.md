# rc-x509-test-client-harness

This crate provides an integration test harness to drive instances of
`rc-x509-client`.

## Versioning

This crate is published with versions matching the `rc-x509-client` version it
targets exactly (`={version}`).

This allows specifying _which version_ of the client library to test against
when importing this crate:

```toml
[dependencies]
# Test rc-x509-client version 0.2.0:
rc-x509-test-client-0-2-0 = { version = "=0.2.0", package = "rc-x509-client" }

# Test rc-x509-client version 0.2.1:
rc-x509-test-client-0-2-1 = { version = "=0.2.1", package = "rc-x509-client" }
```

You can then target specific versions by using the respective package:

```rust,ignore
// A client running v0.2.0:
let v0_2_0 = rc_x509_test_client_0_2_0::client::TestClient::new();

// A client running v0.2.1:
let v0_2_1 = rc_x509_test_client_0_2_1::client::TestClient::new();
```
