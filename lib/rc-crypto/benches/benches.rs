mod runs;
use runs::*;

use criterion::{criterion_group, criterion_main};

// List benchmarks here.
criterion_group!(benches, key_gen::key_generation, sign::sign);

criterion_main!(benches);
