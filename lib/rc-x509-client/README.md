# rc-x509-client

This library implements the Remote Config client for the X509-based delivery
platform. It handles the low-level networking protocol and security checks,
while delegating message processing to the host application.

## Design Goals

* Low overhead connection management and message attestation.
* Reusable public API, wrapped in a simple FFI API (see `rc-x509-ffi`).
* Fully encapsulate all RPC protocol messaging and logic, but not the actual I/O
  (delegated to host language runtime).