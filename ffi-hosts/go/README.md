> [!TIP]
If you just want to see the Go X509 client, go to the [`rcx509`](rcx509/) dir.

# libdd-rc Go host

`rcx509` is the public Go API for libdd-rc. It wraps `internal/libddrcffi`,
the Go bindings for the libdd-rc C FFI interface (`include/libdd_rc.h`),
built via cgo against a statically linked `rc-x509-ffi` archive.
`internal/libddrcffi` is not intended to be used directly outside this
module; callers should use `rcx509`.

## Building

This client uses cgo, so downstream builds must use `CGO_ENABLED=1` and provide
native artifacts built from the same libdd-rc revision as the Go module:

- `libdd_rc.h` on the C compiler's include path
- `librc_x509_ffi.a` on the native linker's library path
- the version-agnostic AWS-LC FIPS crypto library (`libaws_lc_fips_crypto`)
  on the linker path and, if it is a shared library, the runtime loader path.
  If `librc_x509_ffi` was built with the `non-fips` feature there is no such
  library; build with `-tags rcx509_nonfips` instead.

These native artifacts are not included in the Go module. 

To build a native artifact, perform a libdd-rc checkout and from the repo root
run `make -C ffi-hosts/go build`; add `FIPS=0` for the non-FIPS build. The
resulting binaries are found under `target/release`. Consumers using another build or packaging system should pass
the header and library locations to cgo (for example through `CGO_CFLAGS` and
`CGO_LDFLAGS`).

## Regenerating Go protobuf bindings

When the `rc-x509-proto` schema changes, regenerate and commit `rcproto` from
the repository root:

```sh
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
buf generate
git add ffi-hosts/go/rcproto
```

CI verifies that the committed bindings remain in sync with the schema.
