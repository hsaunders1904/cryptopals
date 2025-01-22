/// An ECB/CBC detection oracle
use crate::encrypt_aes_128_cbc;
use crate::encrypt_aes_128_ecb;
use crate::Mt19937;

#[derive(Debug, PartialEq, Eq)]
pub enum EncryptionMode {
    ECB,
    CBC,
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut rng = gen_seeded_rng();
    let mut key = [0u8; N];
    key.iter_mut()
        .for_each(|byte| *byte = random_byte(&mut rng));
    key
}

pub fn random_bytes_with_seed<const N: usize>(seed: u32) -> [u8; N] {
    let mut rng = Mt19937::new(seed);
    let mut key = [0u8; N];
    key.iter_mut()
        .for_each(|byte| *byte = random_byte(&mut rng));
    key
}

fn gen_seeded_rng() -> Mt19937 {
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u32;
    Mt19937::new(seed)
}

fn random_byte(rng: &mut Mt19937) -> u8 {
    let u32_val = rng.generate();
    (u32_val & 0b11111111) as u8
}

/// AES encryption oracle that encrypts with ECB or CBC.
pub fn aes_encryption_oracle(bytes: &[u8]) -> (Vec<u8>, EncryptionMode) {
    let key = random_bytes::<16>();
    let mut rng = gen_seeded_rng();
    let n_begin_pad = rng.generate_in_range(5, 10) as usize;
    let n_end_pad = rng.generate_in_range(5, 10) as usize;
    let begin_pad = b"\0".repeat(n_begin_pad);
    let end_pad = b"\0".repeat(n_end_pad);

    // TODO: there must be some way to do this without copying...
    //  Maybe we need to be using iterators and not slices?
    let plaintext = [begin_pad.as_slice(), bytes, end_pad.as_slice()].concat();
    if rng.generate() & 1 == 0 {
        let iv = random_bytes::<16>();
        return (
            encrypt_aes_128_cbc(&plaintext, &key, &iv),
            EncryptionMode::CBC,
        );
    }
    (encrypt_aes_128_ecb(&plaintext, &key), EncryptionMode::ECB)
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;

    use crate::score_aes_ecb_likelihood;

    #[test]
    fn random_key_generates_different_bytes() {
        let key_1 = random_bytes::<16>();
        let key_2 = random_bytes::<16>();

        assert_ne!(key_1, key_2);
    }

    #[test]
    fn ecb_mode_can_be_detected_with_english_plaintext() {
        let mut plaintext_str = String::new();
        std::fs::File::open("./data/set02/c11.txt")
            .unwrap()
            .read_to_string(&mut plaintext_str)
            .unwrap();
        let plaintext = plaintext_str.as_bytes();

        for _ in 0..20 {
            let (ciphertext, mode) = aes_encryption_oracle(plaintext);
            let ecb_score = score_aes_ecb_likelihood(&ciphertext);
            if ecb_score > 1e-5 {
                assert_eq!(mode, EncryptionMode::ECB);
            } else {
                assert_eq!(mode, EncryptionMode::CBC);
            }
        }
    }
}
