# `rc-crypto` Benchmarks

## Running

```shellsession
% cargo bench
```

## Adding New Benches

Copy the existing structure of a benchmark, namely:

* Parameterise benchmarks.
* Explicitly group parametrised benches.
* Use consistent naming across benches.
* Use throughput rates over the parameter to help highlight changes in
  performance over those parameters.

To add a new benchmark:

1. Create a new file in `runs/bananas.rs`.
2. Add it to the `runs/mod.rs` as `pub(crate)`.
3. Create a benchmark function in your file:

```rust
pub(crate) fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("fib 42", |b| b.iter(|| fibonacci(42)));
}
```

4. Link this function into the benchmark suite in `benches.rs` by adding it to
   the `criterion_group!()` statement.

This unifies all benchmarks into one binary, avoiding needing to compile and
link each individually.
