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

### Updating Rust Version

To update the Rust toolchain version used in this project AND in CI, follow the
steps outlined in the doc comments of `.github/images/rust-ci.Dockerfile`.

## Automatic Crate Publishing

The following crates are published to [crates.io] via the
`.github/workflows/publish.yml` workflow:

- `rc-crypto`
- `rc-x509-proto`
- `rc-x509-test-helpers`
- `rc-x509-trust`
- `rc-x509-client`

### How to publish

1. Bump the version in `Cargo.toml` for the crate(s) you want to release. If a
   crate depends on another workspace crate being bumped, update its dependency
   version too.
2. Create a [GitHub release] — the workflow triggers on `release: published`.
3. The workflow authenticates with crates.io using [trusted publishing] (OIDC, no
   API tokens) and publishes the crates in dependency order.

### Setup

The workflow requires a `crates-io` GitHub environment (Settings > Environments)
and a trusted publisher configured on crates.io for each crate (owner:
`DataDog`, repo: `libdd-rc`, workflow: `publish.yml`, environment: `crates-io`).

[crates.io]: https://crates.io
[GitHub release]: https://github.com/DataDog/libdd-rc/releases/new
[trusted publishing]: https://crates.io/docs/trusted-publishing
