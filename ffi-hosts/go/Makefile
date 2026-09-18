.PHONY: generate build test vet runtest

# FFI library source code.
FFI_SRC := $(shell find ../../lib -name '*.rs' -o -name Cargo.toml) ../../Cargo.lock

# FFI library output (compiled library):
FFI_LIB := ../../target/release/librc_x509_ffi.a

# A linker flag that invalidates the Go build cache whenever the FFI library is
# updated.
FFI_LIB_GO_LDFLAGS = -X github.com/DataDog/libdd-rc/ffi-hosts/go/internal/libddrcffi.ffiLibHash=$(shell shasum -a 256 $(FFI_LIB) | cut -d' ' -f1)

# The path to the PoC.
POC_BIN := cmd/bin/testx509
POC_SRC := $(shell find cmd/testx509 -name '*.go')

################################################################################
# Build targets.

# Compile the FFI library.
$(FFI_LIB): $(FFI_SRC)
	cd ../.. && cargo build -p rc-x509-ffi --release
	./scripts/copy_fips_lib.sh

# Compile the Go PoC binary.
$(POC_BIN): generate $(FFI_LIB) $(POC_SRC)
	rm -rf $<
	CGO_ENABLED=1 go build -ldflags="$(FFI_LIB_GO_LDFLAGS)" -o $(POC_BIN) $(POC_SRC)

################################################################################
# User targets.

generate:
	cd ../.. && buf generate

build: generate $(FFI_LIB)
	CGO_ENABLED=1 go build -ldflags="$(FFI_LIB_GO_LDFLAGS)" ./...

test: generate $(FFI_LIB)
	CGO_ENABLED=1 go test -ldflags="$(FFI_LIB_GO_LDFLAGS)" ./...

vet: generate
	CGO_ENABLED=1 go vet ./...

runtest: $(POC_BIN)
	DYLD_LIBRARY_PATH=$(CURDIR)/../../target/release LD_LIBRARY_PATH=$(CURDIR)/../../target/release $(POC_BIN)
