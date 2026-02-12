# rc-crypto

This crate provides cryptographic primitives for use by the X509-based platform,
backed by FIPS compatible crypto modules.

The purpose of this crate is to encapsulate any interaction with an underlying
crypto module, presenting a simple API to consuming crates.

This crate is for wrapping the crypto modules only - not for general code.

# Example Usage

```rust
use rc_crypto::{Signature, Signer, keys::*};

// The data to sign.
let data = "bananas".as_bytes();

// Generate an ephemeral key:
let key = PrivateKey::new();

// Sign the data:
let sig = key.sign(data);

// And verify:
assert!(key.public_key().verify(&data, &sig).is_ok());
```

# Tests

Tests exclusively using the public API live in `tests/`. Each component has unit
tests alongside the implementation.
