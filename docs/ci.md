# CI in libdd-rc

All our CI steps are defined as GitHub Actions in `.github/workflows`.

They typically make use of our custom build image.

## Build Image

To speed up CI, a minimal build environment is maintained as a container image
and published to the GitHub container registry:

	https://github.com/datadog/libdd-rc/pkgs/container/libdd-rc%2Frust-ci

This image is based on the [official Rust container image] (slim).

This image is built from `.github/images/rust-ci.Dockerfile` whenever the
Dockerfile or `rust-toolchain.toml` file changes by the
`.github/workflows/ci-image.yml` workflow.

Additionally the image is rebuilt weekly to update the embedded "nightly"
toolchain, used for miri / fuzzing CI workflows.

[official Rust container image]: https://hub.docker.com/_/rust

### Updating Rust Version

To update the Rust toolchain version used in this project AND in CI, follow the
steps outlined in the doc comments of `.github/images/rust-ci.Dockerfile`.
