.PHONY: generate libffi build test vet

generate:
	cd ../.. && buf generate

libffi:
	cd ../.. && cargo build -p rc-x509-ffi --release
	@fips_lib=$$(find ../../target/release/build \( -name 'libaws_lc_fips_*crypto.dylib' -o -name 'libaws_lc_fips_*crypto.so' -o -name 'libaws_lc_fips_*crypto.a' \) 2>/dev/null | head -n1); \
	if [ -n "$$fips_lib" ]; then \
		cp "$$fips_lib" ../../target/release/; \
	fi

build: generate libffi
	CGO_ENABLED=1 go build ./...

test: generate libffi
	CGO_ENABLED=1 go test ./...

vet: generate libffi
	CGO_ENABLED=1 go vet ./...
