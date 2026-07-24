.PHONY: libffi build test vet

libffi:
	cd ../.. && cargo build -p rc-x509-ffi --release
	@fips_lib=$$(find ../../target/release/build -name 'libaws_lc_fips_*crypto.dylib' -o -name 'libaws_lc_fips_*crypto.so' 2>/dev/null | head -n1); \
	if [ -n "$$fips_lib" ]; then \
		cp "$$fips_lib" ../../target/release/; \
	fi

build: libffi
	CGO_ENABLED=1 go build ./...

test: libffi
	CGO_ENABLED=1 go test ./...

vet: libffi
	CGO_ENABLED=1 go vet ./...
