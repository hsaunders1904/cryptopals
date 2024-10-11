use cryptopals::{brute_force_repeating_xor, hex_to_b64, hex_to_bytes, score_english_by_frequency};

use base64::{self, Engine};
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

pub fn brute_forcing_repeating_xor_cipher(c: &mut Criterion) {
    let data_file = std::path::Path::new("./data/set01/c06.b64");
    let b64_ciphertext = std::fs::read_to_string(data_file)
        .unwrap()
        .replace("\n", "");
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(b64_ciphertext)
        .unwrap();

    c.bench_function("brute_forcing_repeating_xor_cipher", |b| {
        b.iter(|| brute_force_repeating_xor(&ciphertext, 8..33))
    });
}

criterion_group!(
    benches,
    bench_hex_to_b64,
    scoring_text_as_english_by_letter_frequency,
    brute_forcing_repeating_xor_cipher,
);
criterion_main!(benches);
