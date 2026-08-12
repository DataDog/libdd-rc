.PHONY: generate libffi build test vet

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
