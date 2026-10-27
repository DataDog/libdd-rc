> [!TIP]
If you just want to see the Go X509 client, go to the [`rcx509`](rcx509/) dir.

# libdd-rc Go host

`rcx509` is the public Go API for libdd-rc. It wraps `internal/libddrcffi`,
the Go bindings for the libdd-rc C FFI interface (`include/libdd_rc.h`),
built via cgo against a statically linked `rc-x509-ffi` archive.
`internal/libddrcffi` is not intended to be used directly outside this
module; callers should use `rcx509`.

## Building

The Rust static library must be built before the Go package, since cgo
links against `target/release/librc_x509_ffi.a`. This artifact is not
committed to the repo (it's covered by the top-level `.gitignore`) — it must
be rebuilt locally, and `CGO_ENABLED=1` is required since this package uses
cgo. The generated Go protobuf bindings under `rcproto` are committed so the
published Go module contains every package it imports.

Use the provided `Makefile`, which builds the Rust artifact, stages the AWS-LC
FIPS crypto library built by `rc-crypto`'s default `fips` feature, and sets
`CGO_LDFLAGS` so cgo can find both:

```sh
make build
make test
```

## Regenerating Go protobuf bindings

When the `rc-x509-proto` schema changes, regenerate and commit `rcproto` from
the repository root:

```sh
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
buf generate
git add ffi-hosts/go/rcproto
```

CI verifies that the committed bindings remain in sync with the schema.
