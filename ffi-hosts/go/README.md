# libddrcffi — Go bindings for libdd-rc

Go bindings for the libdd-rc C FFI interface (`include/libdd_rc.h`), built
via cgo against a statically linked `rc-x509-ffi` archive. This package is
internal: it's only intended to be used by the Go wrapper built on top of it
in this module.

## Building

The Rust static library must be built before the Go package, since cgo
links against `target/release/librc_x509_ffi.a`. This artifact is not
committed to the repo (it's covered by the top-level `.gitignore`) — it must
be rebuilt locally, and `CGO_ENABLED=1` is required since this package uses
cgo. The `rcproto` package (Go protobuf bindings generated from
`rc-x509-proto`) is likewise not committed and must be regenerated with
`buf generate` before building:

```sh
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
buf generate
cargo build -p rc-x509-ffi --release
CGO_ENABLED=1 go build ./...
CGO_ENABLED=1 go test ./...
```

`rc-crypto`'s default `fips` feature also produces a dynamically linked
AWS-LC FIPS crypto module (FIPS 140 validation requires it to self-verify its
own binary at load time, so it can't ship as a static archive). `bridge.go`
links this by name and rpath, and `make libffi` stages the built `.dylib`/
`.so` next to `librc_x509_ffi.a` so it can be found without extra runtime
configuration.

Or use the provided `Makefile`, which regenerates `rcproto`, builds the Rust
artifact (and stages the FIPS crypto module) first:

```sh
make build
make test
```