use criterion::Criterion;
use rc_crypto::{Signer, keys::PrivateKey};

struct Params {
    name: &'static str,
    size: usize,
}

pub(crate) fn sign(c: &mut Criterion) {
    let runs = [
        Params {
            name: "1b",
            size: 1,
        },
        Params {
            name: "128b",
            size: 128,
        },
        Params {
            name: "1kb",
            size: 1024,
        },
        Params {
            name: "4kb",
            size: 4096,
        },
        Params {
            name: "1mb",
            size: 1024 * 1024,
        },
    ];

    let key = PrivateKey::new();

    for v in runs {
        run(c, v, &key);
    }
}

fn run(c: &mut Criterion, v: Params, key: &PrivateKey) {
    // Generate a payload of the configured size.
    let mut payload = Vec::with_capacity(v.size);
    payload.resize(v.size, 42);

    let mut g = c.benchmark_group("sign");
    g.throughput(criterion::Throughput::Bytes(payload.len() as _));

    g.bench_function(v.name, |b| b.iter(|| key.sign(&payload)));
}
