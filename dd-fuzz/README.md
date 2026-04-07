# Datadog Fuzzing

Continuous fuzzing with the dog.

## Usage

From this directory:

1. Build an image:

```shellsession
% podman build -t libdd-rc-fuzz:ffi_io -f Dockerfile \
	--build-arg FUZZ_DIR="lib/rc-x509-ffi/fuzz" \
	--build-arg FUZZ_TARGET=ffi_io \
	..
```

Or using the helper script:

```shellsession
% ./build.sh
```

2. Run an image:

_(optional: obtain a token for corpus storage)_
```shellsession
% export FUZZYDOG_AUTH_TOKEN=$(ddtool auth token security-fuzzing-platform --datacenter=us1.ddbuild.io)
```

```shellsession
% podman run --rm -it -e FUZZYDOG_AUTH_TOKEN libdd-rc-fuzz:ffi_io:latest
```
