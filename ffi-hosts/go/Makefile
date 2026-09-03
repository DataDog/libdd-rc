.PHONY: generate libffi build test vet runtest

generate:
	cd ../.. && buf generate

libffi:
	cd ../.. && cargo build -p rc-x509-ffi --release
	./scripts/copy_fips_lib.sh

build: generate libffi
	CGO_ENABLED=1 go build ./...

test: generate libffi
	CGO_ENABLED=1 go test ./...

vet: generate libffi
	CGO_ENABLED=1 go vet ./...

# runtest builds and runs cmd/testx509, pointing the dynamic linker at
# target/release so it can find libaws_lc_fips_crypto without relying on
# the rpath baked into the binary at link time.
runtest: generate libffi
	CGO_ENABLED=1 DYLD_LIBRARY_PATH=$(CURDIR)/../../target/release LD_LIBRARY_PATH=$(CURDIR)/../../target/release go run ./cmd/testx509
