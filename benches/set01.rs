use cryptopals::hex_to_b64;

use criterion::{criterion_group, criterion_main, Criterion};

pub fn bench_hex_to_b64(c: &mut Criterion) {
    let hex = std::fs::read_to_string("./benches/data/lorem_ipsum.hex").unwrap();
    c.bench_function("hex_to_b64", |b| b.iter(|| hex_to_b64(&hex)));
}

criterion_group!(benches, bench_hex_to_b64,);
criterion_main!(benches);
