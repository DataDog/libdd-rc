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

# Build Problems

Sometimes aws_lc_rs can suffer from flaky builds. Here's a few known causes and
solutions.

## Missing Symbols

Sometimes aws-lc-rs fails to compile, complaining of undefined symbols. It seems
the build process for the C file can fail such that it leaves an empty
intermediate file, and then never regenerates it after causing a persistent
build error.

Run this:

```shellsession
% cargo clean -p aws-lc-fips-sys -p aws-lc-sys -p aws-lc-rs
```

And then run the build again which should succeed.

## Miri Checks

Not really an aws-lc-rs problem as such, but Miri can't execute the C code
behind the FFI boundary that exists to call the C library for AWS-LC.

Instead, use `#[cfg(miri)]` to sub out AWS-LC calls for miri only.