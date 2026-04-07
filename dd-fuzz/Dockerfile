# Path to the fuzz target.
ARG FUZZ_DIR="lib/rc-x509-ffi/fuzz"
# Name of the fuzz target.
ARG FUZZ_TARGET="ffi_io"

# Tooling version + SHA pin.
ARG FUZZYDOG_VERSION="0.27.1"
ARG FUZZYDOG_HASH="sha256:eeab82c7ff42bededccefe459814ee4114ebe75702bca25602a5c33c72c3a9fd"

# Docs: https://datadoghq.atlassian.net/wiki/spaces/RESENG/pages/6456412103/Recommended+OCI+Dockerfile+setup

# ---------------------------------------------------------------------------
# Builder: compile fuzz targets and extract fuzzydog binary
# ---------------------------------------------------------------------------
FROM registry.ddbuild.io/images/mirror/rust:1.90 AS builder
USER root

# --
# Build fuzz targets.
# --
RUN apt-get update && \
	apt-get install -y --no-install-recommends \
	golang-go cmake clang protobuf-compiler && \
	rm -rf /var/lib/apt/lists/*

RUN cargo install cargo-fuzz

COPY . /src
WORKDIR /src

# Build the specified fuzz target.
ARG FUZZ_DIR
ARG FUZZ_TARGET
RUN cargo +nightly fuzz build --fuzz-dir "${FUZZ_DIR}" && \
	mkdir -p /fuzzer/builds && \
	cp target/*/release/${FUZZ_TARGET} /fuzzer/builds/

# --
# Download fuzzydog tooling.
# --
ARG FUZZYDOG_VERSION
ARG FUZZYDOG_HASH

# Download a pinned, hashed fuzzydog binary.
ADD --checksum="${FUZZYDOG_HASH}" https://binaries.ddbuild.io/fuzzing/fuzzydog/${FUZZYDOG_VERSION}/fuzzydog-tar.tar.gz /tmp/fuzzydog-tar.tar.gz

# https://docs.docker.com/reference/dockerfile#automatic-platform-args-in-the-global-scope
ARG TARGETARCH
ARG TARGETOS

RUN tar -C /usr/local/bin -zxf /tmp/fuzzydog-tar.tar.gz fuzzydog-${TARGETOS}-${TARGETARCH} \
	&& mv /usr/local/bin/fuzzydog-${TARGETOS}-${TARGETARCH} /usr/local/bin/fuzzydog \
	&& rm /tmp/fuzzydog-tar.tar.gz

# ---------------------------------------------------------------------------
# Runtime: minimal image with only the built artifacts
# ---------------------------------------------------------------------------
#
# Image must match debian version in builder stage to use the same glibc.
FROM registry.ddbuild.io/images/mirror/debian:trixie-slim

RUN apt-get update && \
	apt-get install -y --no-install-recommends \
	ca-certificates && \
	rm -rf /var/lib/apt/lists/*

RUN mkdir -p \
	/fuzzer/inputs \
	/fuzzer/crashes \
	/fuzzer/builds && \
	chmod 777 -R /fuzzer

COPY --from=builder /usr/local/bin/fuzzydog /usr/local/bin/fuzzydog
COPY --from=builder /fuzzer/builds/ /fuzzer/builds/

# Drop perms.
USER daemon

ARG FUZZ_TARGET
ENV FUZZ_TARGET=${FUZZ_TARGET}
CMD fuzzydog fuzzer run libdd-rc "${FUZZ_TARGET}" \
	--type libfuzzer \
	--team remote-config \
	--build-path /fuzzer/builds/ \
	--skip-dl-build \
	--skip-dl-inputs \
	--slack-channel fuzzing-ops \
	--repository-url https://github.com/DataDog/libdd-rc
