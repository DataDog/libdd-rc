use criterion::Criterion;
use rc_crypto::keys::PrivateKey;

pub(crate) fn key_generation(c: &mut Criterion) {
    let mut g = c.benchmark_group("ecdsa-p256");
    g.throughput(criterion::Throughput::Elements(1));

    g.bench_function("generate", |b| b.iter(PrivateKey::new));
}
