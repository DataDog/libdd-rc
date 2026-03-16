// Copyright 2026-Present Datadog, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
