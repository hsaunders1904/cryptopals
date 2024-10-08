use cryptopals::{hex_to_b64, hex_to_bytes, score_english_by_frequency};

use criterion::{criterion_group, criterion_main, Criterion};

pub fn bench_hex_to_b64(c: &mut Criterion) {
    let hex = std::fs::read_to_string("./benches/data/lorem_ipsum.hex").unwrap();
    c.bench_function("hex_to_b64", |b| b.iter(|| hex_to_b64(&hex)));
}

pub fn scoring_text_as_english_by_letter_frequency(c: &mut Criterion) {
    let hex = std::fs::read_to_string("./benches/data/lorem_ipsum.hex").unwrap();
    let chars = hex_to_bytes(&hex).unwrap();
    c.bench_function("score_english_by_frequency", |b| {
        b.iter(|| score_english_by_frequency((&chars).iter()))
    });
}

criterion_group!(
    benches,
    bench_hex_to_b64,
    scoring_text_as_english_by_letter_frequency,
);
criterion_main!(benches);
