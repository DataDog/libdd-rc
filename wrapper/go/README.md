# Go Wrapper for libdd-rc

Go language bindings for the Remote Configuration x509 client library.

## Protobuf Generation

Protocol buffer messages are defined in `../../lib/rc-x509-proto/protos/protocol.proto`.

To regenerate the Go bindings:

```bash
go generate ./internal/testproto
```

This requires:
- `protoc` - Install from https://github.com/protocolbuffers/protobuf/releases
- `protoc-gen-go` - Install with `go install google.golang.org/protobuf/cmd/protoc-gen-go@latest`

## Testing

See `client_test.go` for examples. Tests require the Rust FFI library:

```bash
cargo build --package rc-x509-ffi --release
cd wrapper/go
export CGO_LDFLAGS="-L../../target/release"
go test -v ./...
```
