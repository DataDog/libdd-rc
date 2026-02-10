# Adding a New Dependency

When adding a new dependency to this repo:

1. Add the dependency as usual
2. Run `./scripts/generate-3rdparty-licenses.sh` to update `LICENSE-3rdparty.csv`
3. Run `./scripts/check-3rdparty-licenses.sh` to verify the license is approved
4. Commit your changes and include `LICENSE-3rdparty.csv`.
