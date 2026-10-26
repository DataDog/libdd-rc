# FFI library output (compiled library):
FFI_LIB := ../../target/release/librc_x509_ffi.a

# Tell cgo where this checkout's FFI library and the AWS-LC FIPS library staged
# by scripts/copy_fips_lib.sh live, with an rpath for running local binaries.
FFI_LIB_DIR := $(abspath ../../target/release)
export CGO_LDFLAGS := -L$(FFI_LIB_DIR) -Wl,-rpath,$(FFI_LIB_DIR)

# Hashing tool for the FFI library; shasum isn't present everywhere (e.g. the
# Linux CI image), coreutils' sha256sum isn't present on macOS.
SHA256 := $(shell command -v shasum >/dev/null 2>&1 && echo 'shasum -a 256' || echo sha256sum)

# A linker flag that invalidates the Go build cache whenever the FFI library is
# updated.
FFI_LIB_GO_LDFLAGS = -X github.com/DataDog/libdd-rc/ffi-hosts/go/internal/libddrcffi.ffiLibHash=$(shell $(SHA256) $(FFI_LIB) | cut -d' ' -f1)

# The path to the PoC.
POC_BIN := cmd/bin/testx509
POC_SRC := $(shell find cmd/testx509 -name '*.go')

.PHONY: generate build test vet runtest ffi-lib $(POC_BIN)

################################################################################
# Build targets.

# Compile the FFI library.
#
# This is always invoked, delegating the "is a rebuild needed" decision to
# cargo. Gating it on the mtime of $(FFI_LIB) is not sufficient: that library
# is only one of the two this host links against, and a target/ directory
# restored from a CI cache can contain a fresh-looking $(FFI_LIB) without the
# aws-lc-fips library the script below copies into place.
ffi-lib:
	cd ../.. && cargo build -p rc-x509-ffi --release
	./scripts/copy_fips_lib.sh

# Compile the Go PoC binary.
$(POC_BIN): ffi-lib $(POC_SRC)
	rm -rf $@
	CGO_ENABLED=1 go build -ldflags="$(FFI_LIB_GO_LDFLAGS)" -o $(POC_BIN) $(POC_SRC)

################################################################################
# User targets.

generate:
	cd ../.. && buf generate

build: ffi-lib
	CGO_ENABLED=1 go build -ldflags="$(FFI_LIB_GO_LDFLAGS)" ./...

test: ffi-lib
	CGO_ENABLED=1 go test -ldflags="$(FFI_LIB_GO_LDFLAGS)" ./...

vet:
	CGO_ENABLED=1 go vet ./...

runtest: $(POC_BIN)
	DYLD_LIBRARY_PATH=$(CURDIR)/../../target/release LD_LIBRARY_PATH=$(CURDIR)/../../target/release $(POC_BIN)
