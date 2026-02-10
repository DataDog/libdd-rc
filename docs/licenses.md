# Licensing

All source files must have the Apache 2.0 header, you can add this manually or
by using [SkyWalking Eyes]:

```shellsession
% brew install license-eye
% license-eye header fix
```

[SkyWalking Eyes]: https://github.com/apache/skywalking-eyes

## 1st Party

All 1st party crates should have `license = "Apache-2.0"` set in their
Cargo.toml files.

This is verified by the `scripts/check-1stparty-crate-licenses.sh` helper in CI.

## 3rd Party

All 3rd party dependencies, and their licenses must be listed in the
`LICENSE-3rdparty.csv` file at the repo root.

You can regenerate this file using the helper script:

```shellsession
% scripts/generate-3rdparty-licenses.sh
```
