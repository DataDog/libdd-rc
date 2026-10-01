# Fuzzing

Run a fuzz session for a specific target with:

```shellsession
RUSTFLAGS="--cfg tracing_unstable" cargo +nightly fuzz run $FUZZ_NAME
```
