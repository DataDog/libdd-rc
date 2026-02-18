# rc-x509-client

This library implements the canonical Remote Config client for the X509-based
delivery platform.

## Design Goals

* Secure cryptographic attestation of messages from the X509 platform.
* Provide a clean, hard-to-misuse FFI API suitable for use across all languages
  supported by Datadog.
* Fully encapsulate all RPC protocol messaging and logic, but not the actual I/O
  (delegated to host language runtime).

