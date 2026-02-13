# Licensing

## Source Code Headers

All source files must have the Apache 2.0 header, you can add this manually or
by using [SkyWalking Eyes]:

```shellsession
% brew install license-eye
% license-eye header fix
```

This lint can be configured in `.licenserc.yaml` to skip specific files.

[SkyWalking Eyes]: https://github.com/apache/skywalking-eyes

## 1st Party Crates

All 1st party crates should have `license = "Apache-2.0"` set in their
Cargo.toml files.

This is verified by in CI using the helper script:

```shellsession
% scripts/check-crate-licenses.sh
```

## 3rd Party Dependencies

All 3rd party dependencies, and their licenses must be listed in the
`LICENSE-3rdparty.csv` file at the repo root.

You can regenerate this file using the helper script:

```shellsession
% scripts/generate-3rdparty-licenses.sh
```

Only dependencies with approved licenses are allowed, this is enforced in CI by
running checking the content of the `LICENSE-3rdparty.csv` file using this
helper:

```shellsession
% scripts/check-3rdparty-licenses.sh
```

### Merge Conflicts

Merge conflicts in this file are not uncommon. These conflicts can be handled
automatically (locally) if you install the merge helper:

```shellsession
% ./scripts/setup-git-merge-drivers.sh
```

You only need to run this script once after cloning the repo.
