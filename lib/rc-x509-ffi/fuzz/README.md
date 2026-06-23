# FFI Fuzzing

Run a fuzz session for a specific target with:

```shellsession
RUSTFLAGS="--cfg tracing_unstable" cargo +nightly fuzz run $FUZZ_NAME
```

See the comments in each of the individual targets for target-specific details.
