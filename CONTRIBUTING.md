# Welcome

Welcome! We are glad you are interested in contributing to libdd-rc. This guide
will help you understand the requirements and guidelines to improve your
contributor experience.

## Contributing to code

### Signing commits

Datadog requires all contributors to sign their commits. If you don't currently
sign your commits, follow [GitHub's documentation on how to set up your signing
keys and start signing your commits][signing].

[signing]:
    https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits

## Adding a New Dependency

When adding a new dependency to this repo:

1. Add the dependency as usual
2. Run `./scripts/generate-3rdparty-licenses.sh` to update `LICENSE-3rdparty.csv`
3. Run `./scripts/check-3rdparty-licenses.sh` to verify the license is approved
4. Commit your changes and include `LICENSE-3rdparty.csv`.
